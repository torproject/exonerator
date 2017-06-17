/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.exonerator;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorCollector;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.ExitList.Entry;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

import org.apache.commons.codec.binary.Hex;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;

/* Import Tor descriptors into the ExoneraTor database. */
public class ExoneraTorDatabaseImporter {

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
      System.err.println("Could not find config file.  Exiting.");
      System.exit(1);
    }
    String line = null;
    try {
      BufferedReader br = new BufferedReader(new FileReader(configFile));
      while ((line = br.readLine()) != null) {
        if (line.startsWith("#") || line.length() < 1) {
          continue;
        } else if (line.startsWith("ExoneraTorDatabaseJdbc")) {
          jdbcString = line.split(" ")[1];
        } else if (line.startsWith("ExoneraTorImportDirectory")) {
          importDirString = line.split(" ")[1];
        } else {
          /* Ignore unrecognized configuration keys. */
        }
      }
      br.close();
    } catch (IOException e) {
      System.err.println("Could not parse config file.  Exiting.");
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
      System.out.println("Could not connect to database.  Exiting.");
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
          "{call insert_statusentry(?, ?, ?, ?, ?, ?, ?)}");
      insertExitlistentryStatement = connection.prepareCall(
          "{call insert_exitlistentry(?, ?, ?, ?, ?)}");
    } catch (SQLException e) {
      System.out.println("Could not prepare callable statements to "
          + "import data into the database.  Exiting.");
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
        long runStarted = Long.parseLong(br.readLine());
        br.close();
        if (System.currentTimeMillis() - runStarted
            < 6L * 60L * 60L * 1000L) {
          System.out.println("File 'exonerator-lock' is less than 6 "
              + "hours old.  Exiting.");
          System.exit(1);
        } else {
          System.out.println("File 'exonerator-lock' is at least 6 hours "
              + "old.  Overwriting and executing anyway.");
        }
      }
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          "exonerator-lock"));
      bw.append(String.valueOf(System.currentTimeMillis()) + "\n");
      bw.close();
    } catch (IOException e) {
      System.out.println("Could not create 'exonerator-lock' file.  "
          + "Exiting.");
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
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            parseHistoryFile));
        String line = null;
        int lineNumber = 0;
        while ((line = br.readLine()) != null) {
          lineNumber++;
          String[] parts = line.split(",");
          if (parts.length != 2) {
            System.out.println("File 'stats/exonerator-import-history' "
                + "contains a corrupt entry in line " + lineNumber
                + ".  Ignoring parse history file entirely.");
            lastImportHistory.clear();
            br.close();
            return;
          }
          long lastModified = Long.parseLong(parts[0]);
          String filename = parts[1];
          lastImportHistory.put(filename, lastModified);
        }
        br.close();
      } catch (IOException e) {
        System.out.println("Could not read import history.  Ignoring.");
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
    Iterator<Descriptor> descriptors = descriptorReader.readDescriptors(
        new File(importDirString)).iterator();
    while (descriptors.hasNext()) {
      Descriptor descriptor = descriptors.next();
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

  /* Date format to parse UTC timestamps. */
  private static SimpleDateFormat parseFormat;

  static {
    parseFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    parseFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  /* Parse a consensus. */
  private static void parseConsensus(RelayNetworkStatusConsensus consensus) {
    for (NetworkStatusEntry entry : consensus.getStatusEntries().values()) {
      if (entry.getFlags().contains("Running")) {
        Set<String> orAddresses = new HashSet<>();
        orAddresses.add(entry.getAddress());
        for (String orAddressAndPort : entry.getOrAddresses()) {
          orAddresses.add(orAddressAndPort.substring(0,
              orAddressAndPort.lastIndexOf(":")));
        }
        importStatusentry(consensus.getValidAfterMillis(),
            entry.getFingerprint().toLowerCase(),
            entry.getDescriptor().toLowerCase(),
            orAddresses, entry.getStatusEntryBytes());
      }
    }
  }

  /* UTC calendar for importing timestamps into the database. */
  private static Calendar calendarUTC = Calendar.getInstance(
      TimeZone.getTimeZone("UTC"));

  /* Import a status entry with one or more OR addresses into the
   * database. */
  private static void importStatusentry(long validAfterMillis,
      String fingerprint, String descriptor, Set<String> orAddresses,
      byte[] rawStatusentry) {
    try {
      for (String orAddress : orAddresses) {
        insertStatusentryStatement.clearParameters();
        insertStatusentryStatement.setTimestamp(1,
            new Timestamp(validAfterMillis), calendarUTC);
        insertStatusentryStatement.setString(2, fingerprint);
        insertStatusentryStatement.setString(3, descriptor);
        if (!orAddress.contains(":")) {
          String[] addressParts = orAddress.split("\\.");
          byte[] address24Bytes = new byte[3];
          address24Bytes[0] = (byte) Integer.parseInt(addressParts[0]);
          address24Bytes[1] = (byte) Integer.parseInt(addressParts[1]);
          address24Bytes[2] = (byte) Integer.parseInt(addressParts[2]);
          String orAddress24 = Hex.encodeHexString(address24Bytes);
          insertStatusentryStatement.setString(4, orAddress24);
          insertStatusentryStatement.setNull(5, Types.VARCHAR);
          insertStatusentryStatement.setString(6, orAddress);
        } else {
          StringBuilder addressHex = new StringBuilder();
          int start = orAddress.startsWith("[::") ? 2 : 1;
          int end = orAddress.length()
              - (orAddress.endsWith("::]") ? 2 : 1);
          String[] parts = orAddress.substring(start, end).split(":", -1);
          for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.length() == 0) {
              addressHex.append("x");
            } else if (part.length() <= 4) {
              addressHex.append(String.format("%4s", part));
            } else {
              addressHex = null;
              break;
            }
          }
          String orAddress48 = null;
          if (addressHex != null) {
            String addressHexString = addressHex.toString();
            addressHexString = addressHexString.replaceFirst("x",
                String.format("%" + (33 - addressHexString.length())
                + "s", "0"));
            if (!addressHexString.contains("x")
                && addressHexString.length() == 32) {
              orAddress48 = addressHexString.replaceAll(" ", "0")
                  .toLowerCase().substring(0, 12);
            }
          }
          if (orAddress48 != null) {
            insertStatusentryStatement.setNull(4, Types.VARCHAR);
            insertStatusentryStatement.setString(5, orAddress48);
            insertStatusentryStatement.setString(6,
                orAddress.replaceAll("[\\[\\]]", ""));
          } else {
            System.err.println("Could not import status entry with IPv6 "
                + "address '" + orAddress + "'.  Exiting.");
            System.exit(1);
          }
        }
        insertStatusentryStatement.setBytes(7, rawStatusentry);
        insertStatusentryStatement.execute();
      }
    } catch (SQLException e) {
      System.out.println("Could not import status entry.  Exiting.");
      System.exit(1);
    }
  }

  private static final byte[] IGNORED_RAW_EXITLIST_ENTRY = new byte[0];

  /* Parse an exit list. */
  private static void parseExitList(ExitList exitList) {
    for (Entry entry : exitList.getEntries()) {
      for (Map.Entry<String, Long> e : entry.getExitAddresses().entrySet()) {
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
        long scannedMillis = e.getValue();
        importExitlistentry(entry.getFingerprint().toLowerCase(), exitAddress24,
            exitAddress, scannedMillis, IGNORED_RAW_EXITLIST_ENTRY);
      }
    }
  }

  /* Import an exit list entry into the database. */
  private static void importExitlistentry(String fingerprint,
      String exitAddress24, String exitAddress, long scannedMillis,
      byte[] rawExitlistentry) {
    try {
      insertExitlistentryStatement.clearParameters();
      insertExitlistentryStatement.setString(1, fingerprint);
      insertExitlistentryStatement.setString(2, exitAddress24);
      insertExitlistentryStatement.setString(3, exitAddress);
      insertExitlistentryStatement.setTimestamp(4,
          new Timestamp(scannedMillis), calendarUTC);
      insertExitlistentryStatement.setBytes(5, rawExitlistentry);
      insertExitlistentryStatement.execute();
    } catch (SQLException e) {
      System.out.println("Could not import exit list entry.  Exiting.");
      System.exit(1);
    }
  }

  /* Write parse history from memory to disk for the next execution. */
  private static void writeImportHistoryToDisk() {
    File parseHistoryFile = new File("stats/exonerator-import-history");
    parseHistoryFile.getParentFile().mkdirs();
    try {
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          parseHistoryFile));
      for (Map.Entry<String, Long> historyEntry :
          nextImportHistory.entrySet()) {
        bw.write(String.valueOf(historyEntry.getValue()) + ","
            + historyEntry.getKey() + "\n");
      }
      bw.close();
    } catch (IOException e) {
      System.out.println("File 'stats/exonerator-import-history' could "
          + "not be written.  Ignoring.");
    }
  }

  /* Close the database connection. */
  private static void closeDatabaseConnection() {
    try {
      connection.close();
    } catch (SQLException e) {
      System.out.println("Could not close database connection.  "
          + "Ignoring.");
    }
  }

  /* Delete the exonerator-lock file to allow the next executing of this
   * tool. */
  private static void deleteLockFile() {
    new File("exonerator-lock").delete();
  }
}

