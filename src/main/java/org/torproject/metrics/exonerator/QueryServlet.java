/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

public class QueryServlet extends HttpServlet {

  private static final long serialVersionUID = 7109011659099295183L;

  private static final Logger logger
      = LoggerFactory.getLogger(QueryServlet.class);

  private DataSource ds;

  private static final DateTimeFormatter validAfterTimeFormatter
      = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
      .withZone(ZoneOffset.UTC);

  @Override
  public void init() {
    /* Look up data source. */
    try {
      Context cxt = new InitialContext();
      this.ds = (DataSource) cxt.lookup("java:comp/env/jdbc/exonerator");
      logger.info("Successfully looked up data source.");
    } catch (NamingException e) {
      logger.warn("Could not look up data source", e);
    }
  }

  @Override
  public void doGet(HttpServletRequest request,
      HttpServletResponse response) throws IOException {
    try {
      /* Parse ip parameter. */
      String ipParameter = request.getParameter("ip");
      if (null == ipParameter) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Missing ip parameter.");
        return;
      }
      String relayIp = this.parseIpParameter(ipParameter);
      if (null == relayIp) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Invalid ip parameter.");
        return;
      }

      /* Parse timestamp parameter. */
      String timestampParameter = request.getParameter("timestamp");
      if (null == timestampParameter) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Missing timestamp parameter.");
        return;
      }
      LocalDate timestamp = this.parseTimestampParameter(timestampParameter);
      if (null == timestamp) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Invalid timestamp parameter.");
        return;
      }
      if (this.checkTimestampTooRecent(timestampParameter)) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Timestamp too recent.");
        return;
      }

      /* Query the database. */
      QueryResponse queryResponse = this.queryDatabase(relayIp, timestamp);
      if (null == queryResponse) {
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
            "Database error.");
      } else {
        /* Write the response. */
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        response.getWriter().write(QueryResponse.toJson(queryResponse));
      }
    } catch (Throwable th) {
      logger.error("Some problem in doGet.  Returning error.", th);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "General backend error.");
    }
  }

  /* Helper methods for handling the request. */

  private String parseIpParameter(String passedIpParameter) {
    String relayIp = null;
    if (passedIpParameter != null && passedIpParameter.length() > 0) {
      String ipParameter = passedIpParameter.trim();
      Pattern ipv4AddressPattern = Pattern.compile(
          "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
          + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
          + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
          + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
      Pattern ipv6AddressPattern = Pattern.compile(
          "^\\[?[0-9a-fA-F:]{3,39}\\]?$");
      if (ipv4AddressPattern.matcher(ipParameter).matches()) {
        String[] ipParts = ipParameter.split("\\.");
        relayIp = Integer.parseInt(ipParts[0]) + "."
            + Integer.parseInt(ipParts[1]) + "."
            + Integer.parseInt(ipParts[2]) + "."
            + Integer.parseInt(ipParts[3]);
      } else if (ipv6AddressPattern.matcher(ipParameter).matches()) {
        if (ipParameter.startsWith("[") && ipParameter.endsWith("]")) {
          ipParameter = ipParameter.substring(1,
              ipParameter.length() - 1);
        }
        StringBuilder addressHex = new StringBuilder();
        int start = ipParameter.startsWith("::") ? 1 : 0;
        int end = ipParameter.length()
            - (ipParameter.endsWith("::") ? 1 : 0);
        String[] parts = ipParameter.substring(start, end).split(":", -1);
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
        if (addressHex != null) {
          String addressHexString = addressHex.toString();
          addressHexString = addressHexString.replaceFirst("x",
              String.format("%" + (33 - addressHexString.length()) + "s",
              "0"));
          if (!addressHexString.contains("x")
              && addressHexString.length() == 32) {
            relayIp = ipParameter.toLowerCase();
          }
        }
      }
    } else {
      relayIp = "";
    }
    return relayIp;
  }

  private String convertIpV4ToHex(String relayIp) {
    String[] relayIpParts = relayIp.split("\\.");
    byte[] address24Bytes = new byte[4];
    for (int i = 0; i < address24Bytes.length; i++) {
      address24Bytes[i] = (byte) Integer.parseInt(relayIpParts[i]);
    }
    return Hex.encodeHexString(address24Bytes);
  }

  private String convertIpV6ToHex(String relayIp) {
    if (relayIp.startsWith("[") && relayIp.endsWith("]")) {
      relayIp = relayIp.substring(1, relayIp.length() - 1);
    }
    StringBuilder addressHex = new StringBuilder();
    int start = relayIp.startsWith("::") ? 1 : 0;
    int end = relayIp.length() - (relayIp.endsWith("::") ? 1 : 0);
    String[] parts = relayIp.substring(start, end).split(":", -1);
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
    String address48 = null;
    if (addressHex != null) {
      String addressHexString = addressHex.toString();
      addressHexString = addressHexString.replaceFirst("x",
          String.format("%" + (33 - addressHexString.length())
          + "s", "0"));
      if (!addressHexString.contains("x")
          && addressHexString.length() == 32) {
        address48 = addressHexString.replace(" ", "0")
            .toLowerCase();
      }
    }
    return address48;
  }

  private LocalDate parseTimestampParameter(
      String passedTimestampParameter) {
    LocalDate timestamp = null;
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setLenient(false);
    if (passedTimestampParameter != null
        && passedTimestampParameter.length() > 0) {
      String timestampParameter = passedTimestampParameter.trim();
      try {
        timestamp = LocalDate.parse(timestampParameter);
      } catch (DateTimeException e) {
        timestamp = null;
      }
    }
    return timestamp;
  }


  /** Return whether the timestamp parameter is too recent, which is the case if
   * it matches the day before the current system date (in UTC) or is even
   * younger. */
  private boolean checkTimestampTooRecent(String timestampParameter) {
    return timestampParameter.compareTo(LocalDate.now(ZoneOffset.UTC)
        .minusDays(1).toString()) >= 0;
  }

  /* Helper methods for querying the database. */

  private QueryResponse queryDatabase(String relayIp, LocalDate timestamp) {

    /* Convert address to hex. */
    String addressHex = !relayIp.contains(":")
        ? this.convertIpV4ToHex(relayIp) : this.convertIpV6ToHex(relayIp);
    if (addressHex == null) {
      return null;
    }
    String address24Hex = addressHex.substring(0, 6);

    /* Store all dates contained in the query response in order to populate the
     * {first|last}_date_in_database and relevant_statuses fields. */
    SortedSet<LocalDate> allDates = new TreeSet<>();

    /* Store all possible matches for the results table by base64-encoded
     * fingerprint and valid-after time. This map is first populated by going
     * through the result set and adding or updating map entries, so that
     * there's one entry per fingerprint and valid-after time with one or more
     * addresses. In a second step, exit addresses are added to map entries. */
    SortedMap<String, SortedMap<LocalDateTime, QueryResponse.Match>>
        matchesByFingerprintBase64AndValidAfter = new TreeMap<>();

    /* Store all possible matches by address. This map has two purposes: First,
     * the query returns all entries matching the first 24 bits of an address,
     * which may include other addresses than the one being looked for. This map
     * then has only those matches that are relevant. Second, if there are no
     * matches for the given address, this map may contain nearby addresses in
     * the same /24 or /48 that can be included in the nearby_addresses
     * field. */
    SortedMap<String, Set<QueryResponse.Match>>
        matchesByAddress = new TreeMap<>();

    /* Store all exit addresses by base64-encoded fingerprint and scanned
     * time. These addresses are added to this map while going through the
     * result set and later added to the two maps above containing matches. The
     * reason for separating these steps is that the result set may contain
     * status entries and exit list entries in any specific order. */
    SortedMap<String, SortedMap<LocalDateTime, String>>
        exitAddressesByFingeprintBase64AndScanned = new TreeMap<>();

    /* Make the database query to populate the sets and maps above. */
    final Instant requestedConnection = Instant.now();
    try (Connection conn = this.ds.getConnection()) {
      try (CallableStatement cs = conn.prepareCall(
          "{call search_by_date_address24(?, ?)}")) {
        cs.setObject(1, timestamp);
        cs.setString(2, address24Hex);
        try (ResultSet rs = cs.executeQuery()) {
          while (rs.next()) {
            LocalDate date = rs.getObject(1, LocalDate.class);
            String fingerprintBase64 = rs.getString(2);
            LocalDateTime scanned = rs.getObject(3, LocalDateTime.class);
            String exitAddress = rs.getString(4);
            LocalDateTime validAfter = rs.getObject(5, LocalDateTime.class);
            String nickname = rs.getString(6);
            Boolean exit = rs.getBoolean(7);
            String orAddress = rs.getString(8);
            if (null != date) {
              allDates.add(date);
            } else if (null != scanned) {
              exitAddressesByFingeprintBase64AndScanned.putIfAbsent(
                  fingerprintBase64, new TreeMap<>());
              exitAddressesByFingeprintBase64AndScanned.get(fingerprintBase64)
                  .put(scanned, exitAddress);
            } else if (null != validAfter) {
              matchesByFingerprintBase64AndValidAfter.putIfAbsent(
                  fingerprintBase64, new TreeMap<>());
              if (!matchesByFingerprintBase64AndValidAfter
                  .get(fingerprintBase64).containsKey(validAfter)) {
                String validAfterString = validAfter.format(
                    validAfterTimeFormatter);
                String fingerprint = Hex.encodeHexString(Base64.decodeBase64(
                    fingerprintBase64 + "=")).toUpperCase();
                matchesByFingerprintBase64AndValidAfter.get(fingerprintBase64)
                    .put(validAfter, new QueryResponse.Match(
                        validAfterString, new TreeSet<>(), fingerprint,
                        nickname, exit));
              }
              QueryResponse.Match match
                  = matchesByFingerprintBase64AndValidAfter
                  .get(fingerprintBase64).get(validAfter);
              if (orAddress.contains(":")) {
                match.addresses.add("[" + orAddress + "]");
              } else {
                match.addresses.add(orAddress);
              }
              matchesByAddress.putIfAbsent(orAddress, new HashSet<>());
              matchesByAddress.get(orAddress).add(match);
            }
          }
        } catch (SQLException e) {
          logger.warn("Result set error.  Returning 'null'.", e);
          return null;
        }
        logger.info("Returned a database connection to the pool after {}.",
            Duration.between(requestedConnection, Instant.now()));
      } catch (SQLException e) {
        logger.warn("Callable statement error.  Returning 'null'.", e);
        return null;
      }
    } catch (Throwable e) { // Catch all problems left.
      logger.warn("Database error.  Returning 'null'.", e);
      return null;
    }

    /* Go through exit addresses and update possible matches. */
    for (Map.Entry<String, SortedMap<LocalDateTime, String>> e
        : exitAddressesByFingeprintBase64AndScanned.entrySet()) {
      String fingerprintBase64 = e.getKey();
      if (!matchesByFingerprintBase64AndValidAfter.containsKey(
          fingerprintBase64)) {
        /* This is a rare edge case where an exit list entry exists, but where
         * that relay was not included in any consensus with a valid-after time
         * of up to 24 hours after the scan time. This match is not supposed to
         * show up in the results, nor should the exit address show up in
         * nearby matches. We'll just skip it. */
        continue;
      }
      for (Map.Entry<LocalDateTime, String> e1 : e.getValue().entrySet()) {
        LocalDateTime scanned = e1.getKey();
        String exitAddress = e1.getValue();
        for (QueryResponse.Match match
            : matchesByFingerprintBase64AndValidAfter.get(fingerprintBase64)
            .subMap(scanned, scanned.plusDays(1L)).values()) {
          match.addresses.add(exitAddress);
          matchesByAddress.putIfAbsent(exitAddress, new HashSet<>());
          matchesByAddress.get(exitAddress).add(match);
        }
      }
    }

    /* Write all results to a new QueryResponse object. */
    final QueryResponse response = new QueryResponse();
    response.queryAddress = relayIp;
    response.queryDate = timestamp.format(DateTimeFormatter.ISO_DATE);
    if (!allDates.isEmpty()) {
      response.firstDateInDatabase = allDates.first()
          .format(DateTimeFormatter.ISO_DATE);
      response.lastDateInDatabase = allDates.last()
          .format(DateTimeFormatter.ISO_DATE);
      response.relevantStatuses = allDates.contains(timestamp)
          || allDates.contains(timestamp.minusDays(1L))
          || allDates.contains(timestamp.plusDays(1L));
    }
    if (matchesByAddress.containsKey(relayIp)) {
      List<QueryResponse.Match> matchesList
          = new ArrayList<>(matchesByAddress.get(relayIp));
      matchesList.sort((m1, m2) -> {
        if (m1 == m2) {
          return 0;
        } else if (!m1.timestamp.equals(m2.timestamp)) {
          return m1.timestamp.compareTo(m2.timestamp);
        } else {
          return m1.fingerprint.compareTo(m2.fingerprint);
        }
      });
      response.matches = matchesList.toArray(new QueryResponse.Match[0]);
    } else {
      SortedSet<String> nearbyAddresses = new TreeSet<>();
      String relayIpHex24Or48 = !relayIp.contains(":")
          ? this.convertIpV4ToHex(relayIp).substring(0, 6)
          : this.convertIpV6ToHex(relayIp).substring(0, 12);
      for (String address : matchesByAddress.keySet()) {
        String nearbyAddressHex24Or48 = !address.contains(":")
            ? this.convertIpV4ToHex(address).substring(0, 6)
            : this.convertIpV6ToHex(address).substring(0, 12);
        if (relayIpHex24Or48.equals(nearbyAddressHex24Or48)) {
          nearbyAddresses.add(address);
        }
      }
      if (!nearbyAddresses.isEmpty()) {
        response.nearbyAddresses = nearbyAddresses.toArray(new String[0]);
      }
    }

    return response;
  }
}

