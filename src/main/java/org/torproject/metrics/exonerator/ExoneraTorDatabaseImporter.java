/* Copyright 2011--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorCollector;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.ExitList.Entry;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/* Import Tor descriptors into the ExoneraTor database. */
public class ExoneraTorDatabaseImporter {

  private static Logger logger
      = LoggerFactory.getLogger(ExoneraTorDatabaseImporter.class);

  /** Main function controlling the parsing process. */
  public static void main(String[] args) {
    readConfiguration();
    openDatabaseConnection();
    prepareDatabaseStatements();
    createLockFile();
    fetchDescriptors();
    readImportHistoryToMemory();
    parseDescriptors();
    writeImportHistoryToDisk();
    closeDatabaseConnection();
    deleteLockFile();
  }

  /* JDBC string of the ExoneraTor database. */
  private static String jdbcString;

  /* Directory from which to import descriptors. */
  private static String importDirString;

  /* Learn JDBC string and directory to parse descriptors from. */
  private static void readConfiguration() {
    File configFile = new File("config");
    if (!configFile.exists()) {
      logger.error("Could not find config file.  Exiting.");
      System.exit(1);
    }
    String line;
    try {
      BufferedReader br = new BufferedReader(new FileReader(configFile));
      while ((line = br.readLine()) != null) {
        if (line.startsWith("ExoneraTorDatabaseJdbc")) {
          jdbcString = line.split(" ")[1];
        } else if (line.startsWith("ExoneraTorImportDirectory")) {
          importDirString = line.split(" ")[1];
        }
      }
      br.close();
    } catch (IOException e) {
      logger.error("Could not parse config file.  Exiting.", e);
      System.exit(1);
    }
  }

  /* Database connection. */
  private static Connection connection;

  /* Open a database connection using the JDBC string in the config. */
  private static void openDatabaseConnection() {
    try {
      connection = DriverManager.getConnection(jdbcString);
    } catch (SQLException e) {
      logger.error("Could not connect to database.  Exiting.", e);
      System.exit(1);
    }
  }

  /* Callable statements to import data into the database. */
  private static CallableStatement insertStatusentryStatement;

  private static CallableStatement insertExitlistentryStatement;

  /* Prepare statements for importing data into the database. */
  private static void prepareDatabaseStatements() {
    try {
      insertStatusentryStatement = connection.prepareCall(
          "{call insert_statusentry_oraddress(?, ?, ?, ?, ?, ?)}");
      insertExitlistentryStatement = connection.prepareCall(
          "{call insert_exitlistentry_exitaddress(?, ?, ?, ?)}");
    } catch (SQLException e) {
      logger.warn("Could not prepare callable statements to "
                  + "import data into the database.  Exiting.", e);
      System.exit(1);
    }
  }

  /* Create a local lock file to prevent other instances of this import
   * tool to run concurrently. */
  private static void createLockFile() {
    File lockFile = new File("exonerator-lock");
    try {
      if (lockFile.exists()) {
        BufferedReader br = new BufferedReader(new FileReader(lockFile));
        Instant runStarted = Instant.ofEpochMilli(Long.parseLong(
            br.readLine()));
        br.close();
        if (runStarted.plus(Duration.ofHours(6L))
            .compareTo(Instant.now()) >= 0) {
          logger.warn("File 'exonerator-lock' is less than 6 "
              + "hours old.  Exiting.");
          System.exit(1);
        } else {
          logger.warn("File 'exonerator-lock' is at least 6 hours old."
              + "  Overwriting and executing anyway.");
        }
      }
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          "exonerator-lock"));
      bw.append(String.valueOf(System.currentTimeMillis())).append("\n");
      bw.close();
    } catch (IOException e) {
      logger.warn("Could not create 'exonerator-lock' file.  Exiting.");
      System.exit(1);
    }
  }

  /* Fetch recent descriptors from CollecTor. */
  private static void fetchDescriptors() {
    DescriptorCollector collector =
        DescriptorSourceFactory.createDescriptorCollector();
    collector.collectDescriptors("https://collector.torproject.org",
        new String[] { "/recent/relay-descriptors/consensuses/",
            "/recent/exit-lists/" }, 0L, new File(importDirString), true);
  }

  /* Last and next parse histories containing paths of parsed files and
   * last modified times. */
  private static SortedMap<String, Long> lastImportHistory = new TreeMap<>();

  private static SortedMap<String, Long> nextImportHistory = new TreeMap<>();

  /* Read stats/exonerator-import-history file from disk and remember
   * locally when files were last parsed. */
  private static void readImportHistoryToMemory() {
    File parseHistoryFile = new File("stats",
        "exonerator-import-history");
    if (parseHistoryFile.exists()) {
      try (BufferedReader br = new BufferedReader(new FileReader(
            parseHistoryFile))) {
        String line;
        int lineNumber = 0;
        while ((line = br.readLine()) != null) {
          lineNumber++;
          String[] parts = line.split(",");
          if (parts.length != 2) {
            logger.warn("File 'stats/exonerator-import-history' "
                + "contains a corrupt entry in line {}.  "
                + "Ignoring parse history file entirely.", lineNumber);
            lastImportHistory.clear();
            return;
          }
          long lastModified = Long.parseLong(parts[0]);
          String filename = parts[1];
          lastImportHistory.put(filename, lastModified);
        }
      } catch (IOException e) {
        logger.warn("Could not read import history.  Ignoring.", e);
        lastImportHistory.clear();
      }
    }
  }

  /* Parse descriptors in the import directory and its subdirectories. */
  private static void parseDescriptors() {
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.setMaxDescriptorsInQueue(20);
    descriptorReader.setExcludedFiles(lastImportHistory);
    for (Descriptor descriptor : descriptorReader.readDescriptors(
        new File(importDirString))) {
      if (descriptor instanceof RelayNetworkStatusConsensus) {
        parseConsensus((RelayNetworkStatusConsensus) descriptor);
      } else if (descriptor instanceof ExitList) {
        parseExitList((ExitList) descriptor);
      }
    }
    nextImportHistory.putAll(
        descriptorReader.getExcludedFiles());
    nextImportHistory.putAll(descriptorReader.getParsedFiles());
  }

  /* Parse a consensus. */
  private static void parseConsensus(RelayNetworkStatusConsensus consensus) {
    LocalDateTime validAfter = LocalDateTime.ofInstant(Instant.ofEpochMilli(
        consensus.getValidAfterMillis()), ZoneOffset.UTC);
    for (NetworkStatusEntry entry : consensus.getStatusEntries().values()) {
      if (entry.getFlags().contains("Running")) {
        String fingerprintBase64 = null;
        try {
          fingerprintBase64 = Base64.encodeBase64String(
              Hex.decodeHex(entry.getFingerprint().toCharArray()))
              .replaceAll("=", "");
        } catch (DecoderException e) {
          logger.warn("Unable to decode hex fingerprint {} to convert it back "
              + "to base64. Aborting import.", entry.getFingerprint(), e);
          System.exit(1);
        }
        final String nickname = entry.getNickname();
        Boolean exit = null;
        if (null != entry.getDefaultPolicy() && null != entry.getPortList()) {
          exit = "accept".equals(entry.getDefaultPolicy())
              || !"1-65535".equals(entry.getPortList());
        }
        Set<String> orAddresses = new HashSet<>();
        orAddresses.add(entry.getAddress());
        for (String orAddressAndPort : entry.getOrAddresses()) {
          orAddresses.add(orAddressAndPort.substring(0,
              orAddressAndPort.lastIndexOf(":")));
        }
        importStatusentry(validAfter, fingerprintBase64, nickname,
            exit, orAddresses);
      }
    }
  }

  /* Import a status entry with one or more OR addresses into the
   * database. */
  private static void importStatusentry(LocalDateTime validAfter,
      String fingerprintBase64, String nickname, Boolean exit,
      Set<String> orAddresses) {
    try {
      for (String orAddress : orAddresses) {
        insertStatusentryStatement.clearParameters();
        insertStatusentryStatement.setObject(1, validAfter);
        insertStatusentryStatement.setString(2, fingerprintBase64);
        if (!orAddress.contains(":")) {
          insertStatusentryStatement.setString(3, orAddress);
          String[] addressParts = orAddress.split("\\.");
          byte[] address24Bytes = new byte[3];
          address24Bytes[0] = (byte) Integer.parseInt(addressParts[0]);
          address24Bytes[1] = (byte) Integer.parseInt(addressParts[1]);
          address24Bytes[2] = (byte) Integer.parseInt(addressParts[2]);
          String orAddress24 = Hex.encodeHexString(address24Bytes);
          insertStatusentryStatement.setString(4, orAddress24);
        } else {
          StringBuilder addressHex = new StringBuilder();
          int start = orAddress.startsWith("[::") ? 2 : 1;
          int end = orAddress.length()
              - (orAddress.endsWith("::]") ? 2 : 1);
          String[] parts = orAddress.substring(start, end).split(":", -1);
          for (String part : parts) {
            if (part.length() == 0) {
              addressHex.append("x");
            } else if (part.length() <= 4) {
              addressHex.append(String.format("%4s", part));
            } else {
              addressHex = null;
              break;
            }
          }
          String orAddress24 = null;
          if (addressHex != null) {
            String addressHexString = addressHex.toString();
            addressHexString = addressHexString.replaceFirst("x",
                String.format("%" + (33 - addressHexString.length())
                + "s", "0"));
            if (!addressHexString.contains("x")
                && addressHexString.length() == 32) {
              orAddress24 = addressHexString.replaceAll(" ", "0")
                  .toLowerCase().substring(0, 6);
            }
          }
          if (orAddress24 != null) {
            insertStatusentryStatement.setString(3,
                orAddress.replaceAll("[\\[\\]]", ""));
            insertStatusentryStatement.setString(4, orAddress24);
          } else {
            logger.error("Could not import status entry with IPv6 "
                         + "address '{}'.  Exiting.", orAddress);
            System.exit(1);
          }
        }
        insertStatusentryStatement.setString(5, nickname);
        insertStatusentryStatement.setBoolean(6, exit);
        insertStatusentryStatement.execute();
      }
    } catch (SQLException e) {
      logger.error("Could not import status entry.  Exiting.", e);
      System.exit(1);
    }
  }

  /* Parse an exit list. */
  private static void parseExitList(ExitList exitList) {
    for (Entry entry : exitList.getEntries()) {
      for (Map.Entry<String, Long> e : entry.getExitAddresses().entrySet()) {
        String fingerprintBase64 = null;
        try {
          fingerprintBase64 = Base64.encodeBase64String(
              Hex.decodeHex(entry.getFingerprint().toCharArray()))
              .replaceAll("=", "");
        } catch (DecoderException ex) {
          logger.warn("Unable to decode hex fingerprint {} to convert to "
              + "base64. Aborting import.", entry.getFingerprint(), ex);
          System.exit(1);
        }
        String exitAddress = e.getKey();
        /* TODO Extend the following code for IPv6 once the exit list
         * format supports it. */
        String[] exitAddressParts = exitAddress.split("\\.");
        byte[] exitAddress24Bytes = new byte[3];
        exitAddress24Bytes[0] = (byte) Integer.parseInt(
            exitAddressParts[0]);
        exitAddress24Bytes[1] = (byte) Integer.parseInt(
            exitAddressParts[1]);
        exitAddress24Bytes[2] = (byte) Integer.parseInt(
            exitAddressParts[2]);
        String exitAddress24 = Hex.encodeHexString(
            exitAddress24Bytes);
        LocalDateTime scanned = LocalDateTime.ofInstant(
            Instant.ofEpochMilli(e.getValue()), ZoneOffset.UTC);
        importExitlistentry(fingerprintBase64, exitAddress24, exitAddress,
            scanned);
      }
    }
  }

  /* Import an exit list entry into the database. */
  private static void importExitlistentry(String fingerprintBase64,
      String exitAddress24, String exitAddress, LocalDateTime scanned) {
    try {
      insertExitlistentryStatement.clearParameters();
      insertExitlistentryStatement.setString(1, fingerprintBase64);
      insertExitlistentryStatement.setString(2, exitAddress);
      insertExitlistentryStatement.setString(3, exitAddress24);
      insertExitlistentryStatement.setObject(4, scanned);
      insertExitlistentryStatement.execute();
    } catch (SQLException e) {
      logger.error("Could not import exit list entry.  Exiting.", e);
      System.exit(1);
    }
  }

  /* Write parse history from memory to disk for the next execution. */
  private static void writeImportHistoryToDisk() {
    File parseHistoryFile = new File("stats/exonerator-import-history");
    parseHistoryFile.getParentFile().mkdirs();
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(
          parseHistoryFile))) {
      for (Map.Entry<String, Long> historyEntry :
          nextImportHistory.entrySet()) {
        bw.write(historyEntry.getValue() + ","
            + historyEntry.getKey() + "\n");
      }
    } catch (IOException e) {
      logger.warn("File 'stats/exonerator-import-history' could "
          + "not be written.  Ignoring.", e);
    }
  }

  /* Close the database connection. */
  private static void closeDatabaseConnection() {
    try {
      connection.close();
    } catch (SQLException e) {
      logger.warn("Could not close database connection. Ignoring.", e);
    }
  }

  /* Delete the exonerator-lock file to allow the next executing of this
   * tool. */
  private static void deleteLockFile() {
    try {
      Files.delete(Paths.get("exonerator-lock"));
    } catch (IOException e) {
      logger.warn("Could not delete lock file \"exonerator-lock\"", e);
    }
  }
}

