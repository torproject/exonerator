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
import org.torproject.descriptor.UnparseableDescriptor;

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
import java.io.LineNumberReader;
import java.nio.file.Files;
import java.nio.file.Path;
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

  private static final Logger logger
      = LoggerFactory.getLogger(ExoneraTorDatabaseImporter.class);

  /** Main function controlling the parsing process. */
  public static void main(String[] args) {
    logger.info("Starting ExoneraTor database importer.");
    readConfiguration();
    openDatabaseConnection();
    prepareDatabaseStatements();
    createLockFile();
    logger.info("Fetching descriptors from CollecTor.");
    fetchDescriptors();
    logger.info("Importing descriptors into the database.");
    readImportHistoryToMemory();
    parseDescriptors();
    writeImportHistoryToDisk();
    closeDatabaseConnection();
    deleteLockFile();
    logger.info("Terminating ExoneraTor database importer.");
  }

  /* JDBC string of the ExoneraTor database. Never include this in a log
   * message, because it likely contains the database password! */
  private static String jdbcString;

  /* Directory from which to import descriptors. */
  private static File importDirectory;

  /* Learn JDBC string and directory to parse descriptors from. */
  private static void readConfiguration() {
    File configFile = new File("config");
    if (!configFile.exists()) {
      logger.error("Could not find configuration file {}. Make sure that this "
          + "file exists. Exiting.", configFile.getAbsoluteFile());
      System.exit(1);
    }
    try (BufferedReader br = new BufferedReader(new FileReader(configFile))) {
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("ExoneraTorDatabaseJdbc")) {
          jdbcString = line.split(" ")[1];
        } else if (line.startsWith("ExoneraTorImportDirectory")) {
          importDirectory = new File(line.split(" ")[1]);
        }
      }
    } catch (IOException e) {
      logger.error("Caught an I/O exception while reading configuration file "
          + "{}. Make sure that this file is readable. Exiting.",
          configFile.getAbsoluteFile(), e);
      System.exit(1);
    } catch (ArrayIndexOutOfBoundsException e) {
      logger.error("Found invalid entry in configuration file {} containing "
          + "fewer than 2 space-separated parts. Fix that line. Exiting.",
          configFile.getAbsoluteFile());
      System.exit(1);
    }
    if (null == jdbcString || null == importDirectory) {
      logger.error("Missing at least one mandatory line in configuration file "
          + "{}. Be sure to configure ExoneraTorDatabaseJdbc and "
          + "ExoneraTorImportDirectory. Exiting.",
          configFile.getAbsoluteFile());
      System.exit(1);
    }
    logger.debug("Read configuration file {}.", configFile.getAbsoluteFile());
  }

  /* Database connection. */
  private static Connection connection;

  /* Open a database connection using the JDBC string in the config. */
  private static void openDatabaseConnection() {
    try {
      connection = DriverManager.getConnection(jdbcString);
    } catch (SQLException e) {
      logger.error("Caught an SQL exception while connecting to the database. "
          + "Make sure that the database exists and that the configured JDBC "
          + "string is correct.", e);
      System.exit(1);
    }
    logger.debug("Connected to the database.");
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
      logger.error("Caught an SQL exception while preparing callable "
          + "statements for importing data into the database. Make sure that "
          + "the configured database user has permissions to insert data. Also "
          + "make sure that the database uses the correct database schema.", e);
      System.exit(1);
    }
  }

  /* Create a local lock file to prevent other instances of this import
   * tool to run concurrently. */
  private static void createLockFile() {
    File lockFile = new File("exonerator-lock");
    if (lockFile.exists()) {
      try (BufferedReader br = new BufferedReader(new FileReader(lockFile))) {
        Instant runStarted = Instant.ofEpochMilli(Long.parseLong(
            br.readLine()));
        if (runStarted.plus(Duration.ofHours(6L))
            .compareTo(Instant.now()) >= 0) {
          logger.error("Lock file {} is less than 6 hours old. Either make "
              + "sure that there are no other ExoneraTor database importers "
              + "running and manually delete that file, or wait until the file "
              + "is 6 hours old when it will be overwritten automatically. "
              + "Exiting.", lockFile.getAbsoluteFile());
          System.exit(1);
        } else {
          logger.warn("Lock file {} is at least 6 hours old. Overwriting and "
              + "continuing with the database import.",
              lockFile.getAbsoluteFile());
        }
      } catch (IOException e) {
        logger.error("Caught an I/O exception when reading existing lock file "
            + "{}. Make sure that this file is readable. Exiting.",
            lockFile.getAbsoluteFile(), e);
        System.exit(1);
      }
    }
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(lockFile))) {
      bw.append(String.valueOf(System.currentTimeMillis())).append("\n");
    } catch (IOException e) {
      logger.error("Caught an I/O exception when creating lock file {}. Make "
          + "sure that the parent directory exists and that the user running "
          + "the ExoneraTor database importer has permissions to create the "
          + "lock file. Exiting.", lockFile.getAbsoluteFile(), e);
      System.exit(1);
    }
    logger.debug("Created lock file {}.", lockFile.getAbsoluteFile());
  }

  /* Fetch recent descriptors from CollecTor. */
  private static void fetchDescriptors() {
    DescriptorCollector collector =
        DescriptorSourceFactory.createDescriptorCollector();
    collector.collectDescriptors("https://collector.torproject.org",
        new String[] { "/recent/relay-descriptors/consensuses/",
            "/recent/exit-lists/" }, 0L, importDirectory, true);
  }

  /* Last and next parse histories containing paths of parsed files and
   * last modified times. */
  private static SortedMap<String, Long> lastImportHistory = new TreeMap<>();

  private static SortedMap<String, Long> nextImportHistory = new TreeMap<>();

  /* Parse history file. */
  private static File parseHistoryFile = new File("stats",
      "exonerator-import-history");

  /* Read stats/exonerator-import-history file from disk and remember
   * locally when files were last parsed. */
  private static void readImportHistoryToMemory() {
    if (parseHistoryFile.exists()) {
      try (LineNumberReader lnr = new LineNumberReader(new FileReader(
          parseHistoryFile))) {
        String line;
        while ((line = lnr.readLine()) != null) {
          Long lastModified = null;
          String filename = null;
          String[] parts = line.split(",");
          if (parts.length == 2) {
            try {
              lastModified = Long.parseLong(parts[0]);
              filename = parts[1];
            } catch (NumberFormatException e) {
              /* Handle below. */
            }
          }
          if (null != lastModified && null != filename) {
            lastImportHistory.put(filename, lastModified);
          } else {
            logger.warn("Read a corrupt entry in line {} of parse history file "
                + "{}. Ignoring the parse history file entirely and moving on "
                + "by parsing all descriptors in {}.",
                lnr.getLineNumber(), parseHistoryFile.getAbsoluteFile(),
                importDirectory.getAbsoluteFile());
            lastImportHistory.clear();
            return;
          }
        }
      } catch (IOException e) {
        logger.warn("Caught an I/O exception while reading parse history file "
            + "{}. Ignoring the parse history file entirely and moving on "
            + "by parsing all descriptors in {}.",
            parseHistoryFile.getAbsoluteFile(),
            importDirectory.getAbsoluteFile(), e);
        lastImportHistory.clear();
        return;
      }
      logger.debug("Read parse history file {} and extracted {} entries.",
          parseHistoryFile.getAbsoluteFile(), lastImportHistory.size());
    } else {
      logger.debug("Not reading parse history file {}, because it does not yet "
          + "exist.", parseHistoryFile.getAbsoluteFile());
    }
  }

  /* Parse descriptors in the import directory and its subdirectories. */
  private static void parseDescriptors() {
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.setMaxDescriptorsInQueue(20);
    descriptorReader.setExcludedFiles(lastImportHistory);
    int parsedConsensuses = 0;
    int parsedExitLists = 0;
    int unparseableDescriptors = 0;
    for (Descriptor descriptor : descriptorReader.readDescriptors(
        importDirectory)) {
      if (descriptor instanceof RelayNetworkStatusConsensus) {
        parseConsensus((RelayNetworkStatusConsensus) descriptor);
        parsedConsensuses++;
      } else if (descriptor instanceof ExitList) {
        parseExitList((ExitList) descriptor);
        parsedExitLists++;
      } else if (descriptor instanceof UnparseableDescriptor) {
        logger.debug("Found descriptor in {} to be unparseable. Check the "
            + "descriptor parse exception and/or descriptor file for details. "
            + "Skipping.",
            descriptor.getDescriptorFile().getAbsoluteFile(),
            ((UnparseableDescriptor) descriptor).getDescriptorParseException());
        unparseableDescriptors++;
      }
    }
    if (unparseableDescriptors > 0) {
      logger.warn("Found {} descriptors in {} to be unparseable and skipped "
          + "them. Check the debug-level logs and/or descriptor files for "
          + "details. If this happened due to a bug in the parsing code, "
          + "manually delete the parse history file {} and run the database "
          + "importer again. Continuing.", unparseableDescriptors,
          importDirectory.getAbsoluteFile(),
          parseHistoryFile.getAbsoluteFile());
    }
    nextImportHistory.putAll(
        descriptorReader.getExcludedFiles());
    nextImportHistory.putAll(descriptorReader.getParsedFiles());
    logger.debug("Read {} consensuses and {} exit lists from {}.",
        parsedConsensuses, parsedExitLists, importDirectory.getAbsoluteFile());
  }

  /* Parse a consensus. */
  private static void parseConsensus(RelayNetworkStatusConsensus consensus) {
    Instant beforeParsingConsensus = Instant.now();
    LocalDateTime validAfter = LocalDateTime.ofInstant(Instant.ofEpochMilli(
        consensus.getValidAfterMillis()), ZoneOffset.UTC);
    int importedStatusEntries = 0;
    for (NetworkStatusEntry entry : consensus.getStatusEntries().values()) {
      if (entry.getFlags().contains("Running")) {
        String fingerprintBase64 = null;
        try {
          fingerprintBase64 = Base64.encodeBase64String(
              Hex.decodeHex(entry.getFingerprint().toCharArray()))
              .replace("=", "");
        } catch (DecoderException e) {
          logger.error("Caught a decoder exception while converting hex "
              + "fingerprint {} found in consensus with valid-after time {} to "
              + "base64. This looks like a bug. Exiting.",
              entry.getFingerprint(), validAfter, e);
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
              orAddressAndPort.lastIndexOf(':')));
        }
        importStatusentry(validAfter, fingerprintBase64, nickname,
            exit, orAddresses);
        importedStatusEntries++;
      }
    }
    logger.debug("Parsed consensus with valid-after time {} and imported {} "
        + "status entries with the Running flag into the database in {}.",
        validAfter, importedStatusEntries,
        Duration.between(beforeParsingConsensus, Instant.now()));
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
              orAddress24 = addressHexString.replace(" ", "0")
                  .toLowerCase().substring(0, 6);
            }
          }
          if (orAddress24 != null) {
            insertStatusentryStatement.setString(3,
                orAddress.replaceAll("[\\[\\]]", ""));
            insertStatusentryStatement.setString(4, orAddress24);
          } else {
            logger.error("Unable to parse IPv6 address {} found in status "
                + "entry with base64-encoded fingerprint {} in consensus with "
                + "valid-after time {}. This is likely a bug. Exiting.",
                orAddress, fingerprintBase64, validAfter);
            System.exit(1);
          }
        }
        insertStatusentryStatement.setString(5, nickname);
        insertStatusentryStatement.setBoolean(6, exit);
        insertStatusentryStatement.execute();
      }
    } catch (SQLException e) {
      logger.error("Caught an SQL exception while importing status entry with "
          + "base64-encoded fingerprint {} and valid-after time {}. Check the "
          + "exception for details. Exiting.",
          fingerprintBase64, validAfter, e);
      System.exit(1);
    }
  }

  /* Parse an exit list. */
  private static void parseExitList(ExitList exitList) {
    Instant beforeParsingExitList = Instant.now();
    LocalDateTime downloaded = LocalDateTime.ofInstant(Instant.ofEpochMilli(
        exitList.getDownloadedMillis()), ZoneOffset.UTC);
    int importedExitListEntries = 0;
    for (Entry entry : exitList.getEntries()) {
      for (Map.Entry<String, Long> e : entry.getExitAddresses().entrySet()) {
        String fingerprintBase64 = null;
        try {
          fingerprintBase64 = Base64.encodeBase64String(
              Hex.decodeHex(entry.getFingerprint().toCharArray()))
              .replace("=", "");
        } catch (DecoderException ex) {
          logger.error("Caught a decoder exception while converting hex "
              + "fingerprint {} found in exit list downloaded (by CollecTor) "
              + "at {} to base64. This looks like a bug. Exiting.",
              entry.getFingerprint(), downloaded, ex);
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
        importedExitListEntries++;
      }
    }
    logger.debug("Parsed exit list downloaded (by CollecTor) at {} and "
        + "imported {} exit list entries into the database in {}.", downloaded,
        importedExitListEntries,
        Duration.between(beforeParsingExitList, Instant.now()));
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
      logger.error("Caught an SQL exception while importing exit list entry "
          + "with base64-encoded fingerprint {}, exit address {}, and scan "
          + "time {}. Check the exception for details. Exiting.",
          fingerprintBase64, exitAddress, scanned, e);
      System.exit(1);
    }
  }

  /* Write parse history from memory to disk for the next execution. */
  private static void writeImportHistoryToDisk() {
    if (parseHistoryFile.getParentFile().mkdirs()) {
      logger.debug("Created parent directory of parse history file {}.",
          parseHistoryFile.getAbsoluteFile());
    }
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(
          parseHistoryFile))) {
      for (Map.Entry<String, Long> historyEntry :
          nextImportHistory.entrySet()) {
        bw.write(historyEntry.getValue() + ","
            + historyEntry.getKey() + "\n");
      }
    } catch (IOException e) {
      logger.warn("Caught an I/O exception while writing parse history file "
          + "{}. The next execution might not be able to read this parse "
          + "history and will parse all files in {}. Moving on, because there "
          + "is nothing we can do about it.",
          parseHistoryFile, importDirectory.getAbsoluteFile(), e);
    }
    logger.debug("Wrote parse history file {}.",
        parseHistoryFile.getAbsoluteFile());
  }

  /* Close the database connection. */
  private static void closeDatabaseConnection() {
    try {
      connection.close();
      logger.debug("Disconnected from database.");
    } catch (SQLException e) {
      logger.warn("Caught an SQL exception while disconnecting from the "
          + "database. Check the exception for details and ideally log into "
          + "the database manually to check that everything has been imported "
          + "correctly. Ignoring, because we were going to terminate anyway.",
          e);
    }
  }

  /* Delete the exonerator-lock file to allow the next executing of this
   * tool. */
  private static void deleteLockFile() {
    Path lockFile = Paths.get("exonerator-lock");
    try {
      Files.delete(lockFile);
      logger.debug("Deleted lock file {}.", lockFile);
    } catch (IOException e) {
      logger.warn("Caught an I/O exception while deleting lock file {}. This "
          + "might prevent future executions from running until the lock file "
          + "is 6 hours old and overwritten, provided that the file can be "
          + "overwritten. Moving on, because we cannot do anything about it.",
          lockFile, e);
    }
  }
}

