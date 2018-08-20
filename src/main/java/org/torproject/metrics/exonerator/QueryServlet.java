/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import org.apache.commons.codec.binary.Hex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TimeZone;
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

  private Logger logger;

  private DataSource ds;

  private static final long MILLISECONDS_IN_A_DAY = 24L * 60L * 60L * 1000L;

  @Override
  public void init() {
    this.logger = LoggerFactory.getLogger(QueryServlet.class);

    /* Look up data source. */
    try {
      Context cxt = new InitialContext();
      this.ds = (DataSource) cxt.lookup("java:comp/env/jdbc/exonerator");
      this.logger.info("Successfully looked up data source.");
    } catch (NamingException e) {
      this.logger.warn("Could not look up data source", e);
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
      Long timestamp = this.parseTimestampParameter(timestampParameter);
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
    String address24 = Hex.encodeHexString(address24Bytes);
    return address24;
  }

  private String convertIpV6ToHex(String relayIp) {
    if (relayIp.startsWith("[") && relayIp.endsWith("]")) {
      relayIp = relayIp.substring(1, relayIp.length() - 1);
    }
    StringBuilder addressHex = new StringBuilder();
    int start = relayIp.startsWith("::") ? 1 : 0;
    int end = relayIp.length() - (relayIp.endsWith("::") ? 1 : 0);
    String[] parts = relayIp.substring(start, end).split(":", -1);
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
    String address48 = null;
    if (addressHex != null) {
      String addressHexString = addressHex.toString();
      addressHexString = addressHexString.replaceFirst("x",
          String.format("%" + (33 - addressHexString.length())
          + "s", "0"));
      if (!addressHexString.contains("x")
          && addressHexString.length() == 32) {
        address48 = addressHexString.replaceAll(" ", "0")
            .toLowerCase();
      }
    }
    return address48;
  }

  private Long parseTimestampParameter(
      String passedTimestampParameter) {
    Long timestamp = null;
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    dateFormat.setLenient(false);
    if (passedTimestampParameter != null
        && passedTimestampParameter.length() > 0) {
      String timestampParameter = passedTimestampParameter.trim();
      try {
        timestamp = dateFormat.parse(timestampParameter).getTime();
      } catch (ParseException e) {
        timestamp = null;
      }
    }
    return timestamp;
  }


  /** Return whether the timestamp parameter is too recent, which is the case if
   * it matches the day before the current system date (in UTC) or is even
   * younger. */
  private boolean checkTimestampTooRecent(String timestampParameter) {
    return timestampParameter.compareTo(ZonedDateTime.now(ZoneOffset.UTC)
        .toLocalDate().minusDays(1).toString()) >= 0;
  }

  /* Helper methods for querying the database. */

  private QueryResponse queryDatabase(String relayIp, long timestamp) {

    /* Convert address to hex. */
    String addressHex = !relayIp.contains(":")
        ? this.convertIpV4ToHex(relayIp) : this.convertIpV6ToHex(relayIp);
    if (addressHex == null) {
      return null;
    }
    String address24Or48Hex = !relayIp.contains(":")
        ? addressHex.substring(0, 6) : addressHex.substring(0, 12);

    /* Prepare formatting response items. */
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    SimpleDateFormat validAfterTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    validAfterTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    /* Make the database query. */
    SortedSet<Long> allValidAfters = new TreeSet<>();
    List<QueryResponse.Match> matches = new ArrayList<>();
    SortedSet<String> allAddresses = new TreeSet<>();
    final long requestedConnection = System.currentTimeMillis();
    Calendar utcCalendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
    try (Connection conn = this.ds.getConnection()) {
      try (CallableStatement cs = conn.prepareCall(String.format(
          "{call search_by_address%s_date(?, ?)}",
          relayIp.contains(":") ? 48 : 24))) {
        cs.setString(1, address24Or48Hex);
        cs.setDate(2, new java.sql.Date(timestamp), utcCalendar);
        try (ResultSet rs = cs.executeQuery()) {
          while (rs.next()) {
            Timestamp ts = rs.getTimestamp(2, utcCalendar);
            if (null == ts) {
              continue;
            }
            long validafter = ts.getTime();
            allValidAfters.add(validafter);
            byte[] rawstatusentry = rs.getBytes(1);
            if (null == rawstatusentry) {
              continue;
            }
            SortedSet<String> addresses = new TreeSet<>();
            SortedSet<String> addressesHex = new TreeSet<>();
            String nickname = null;
            Boolean exit = null;
            for (String line : new String(rawstatusentry).split("\n")) {
              if (line.startsWith("r ")) {
                String[] parts = line.split(" ");
                nickname = parts[1];
                addresses.add(parts[6]);
                addressesHex.add(this.convertIpV4ToHex(parts[6]));
              } else if (line.startsWith("a ")) {
                String address = line.substring("a ".length(),
                    line.lastIndexOf(":"));
                addresses.add(address);
                String orAddressHex = !address.contains(":")
                    ? this.convertIpV4ToHex(address)
                    : this.convertIpV6ToHex(address);
                addressesHex.add(orAddressHex);
              } else if (line.startsWith("p ")) {
                exit = !line.equals("p reject 1-65535");
              }
            }
            String exitaddress = rs.getString(4);
            if (exitaddress != null && exitaddress.length() > 0) {
              addresses.add(exitaddress);
              addressesHex.add(this.convertIpV4ToHex(exitaddress));
            }
            allAddresses.addAll(addresses);
            if (!addressesHex.contains(addressHex)) {
              continue;
            }
            String validAfterString = validAfterTimeFormat.format(validafter);
            String fingerprint = rs.getString(3).toUpperCase();
            QueryResponse.Match match = new QueryResponse.Match();
            match.timestamp = validAfterString;
            match.addresses = addresses.toArray(new String[0]);
            match.fingerprint = fingerprint;
            match.nickname = nickname;
            match.exit = exit;
            matches.add(match);
          }
        } catch (SQLException e) {
          this.logger.warn("Result set error.  Returning 'null'.", e);
          return null;
        }
        this.logger.info("Returned a database connection to the pool after {}"
            + " millis.", System.currentTimeMillis() - requestedConnection);
      } catch (SQLException e) {
        this.logger.warn("Callable statement error.  Returning 'null'.", e);
        return null;
      }
    } catch (Throwable e) { // Catch all problems left.
      this.logger.warn("Database error.  Returning 'null'.", e);
      return null;
    }

    QueryResponse response = new QueryResponse();
    response.queryAddress = relayIp;
    response.queryDate = dateFormat.format(timestamp);
    if (!allValidAfters.isEmpty()) {
      response.firstDateInDatabase = dateFormat.format(allValidAfters.first());
      response.lastDateInDatabase = dateFormat.format(allValidAfters.last());
      response.relevantStatuses = false;
      long timestampFrom = timestamp - MILLISECONDS_IN_A_DAY;
      long timestampTo = timestamp + 2 * MILLISECONDS_IN_A_DAY - 1L;
      for (long validAfter : allValidAfters) {
        if (validAfter >= timestampFrom && validAfter <= timestampTo) {
          response.relevantStatuses = true;
          break;
        }
      }
      if (!matches.isEmpty()) {
        Collections.sort(matches,
            (m1, m2) -> {
              if (m1 == m2) {
                return 0;
              } else if (!m1.timestamp.equals(m2.timestamp)) {
                return m1.timestamp.compareTo(m2.timestamp);
              } else {
                return m1.fingerprint.compareTo(m2.fingerprint);
              }
            });
        response.matches = matches.toArray(new QueryResponse.Match[0]);
      } else {
        List<String> nearbyAddresses = new ArrayList<>();
        for (String nearbyAddress : allAddresses) {
          String nearbyAddressHex = !nearbyAddress.contains(":")
              ? this.convertIpV4ToHex(nearbyAddress)
              : this.convertIpV6ToHex(nearbyAddress);
          String nearbyAddress24Or48Hex = !nearbyAddress.contains(":")
              ? nearbyAddressHex.substring(0, 6)
              : nearbyAddressHex.substring(0, 12);
          if (address24Or48Hex.equals(nearbyAddress24Or48Hex)) {
            nearbyAddresses.add(nearbyAddress);
          }
        }
        if (!nearbyAddresses.isEmpty()) {
          response.nearbyAddresses = nearbyAddresses.toArray(new String[0]);
        }
      }
    }

    return response;
  }
}

