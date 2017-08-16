/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.exonerator;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

public class QueryServlet extends HttpServlet {

  private static final long serialVersionUID = 7109011659099295183L;

  private Logger logger;

  private DataSource ds;

  @Override
  public void init() {

    /* Initialize logger. */
    this.logger = Logger.getLogger(QueryServlet.class.toString());

    /* Look up data source. */
    try {
      Context cxt = new InitialContext();
      this.ds = (DataSource) cxt.lookup("java:comp/env/jdbc/exonerator");
      this.logger.info("Successfully looked up data source.");
    } catch (NamingException e) {
      this.logger.log(Level.WARNING, "Could not look up data source", e);
    }
  }

  @Override
  public void doGet(HttpServletRequest request,
      HttpServletResponse response) throws IOException,
      ServletException {

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

    /* Query the database. */
    QueryResponse queryResponse = this.queryDatabase(relayIp, timestamp);
    if (null == queryResponse) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "Database error.");
      return;
    }

    /* Format the query response. */
    Gson gson = new Gson();
    String formattedResponse = gson.toJson(queryResponse);

    /* Write the response. */
    response.setContentType("application/json");
    response.setCharacterEncoding("utf-8");
    response.getWriter().write(formattedResponse);
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

  /* Helper methods for querying the database. */

  private QueryResponse queryDatabase(String relayIp, long timestamp) {

    QueryResponse response = null;
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    SimpleDateFormat validAfterTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    validAfterTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    /* Open a database connection that we'll use to handle the whole
     * request. */
    long requestedConnection = System.currentTimeMillis();
    Connection conn = this.connectToDatabase();
    if (null != conn) {

      response = new QueryResponse();
      response.queryAddress = relayIp;
      response.queryDate = dateFormat.format(timestamp);

      /* Look up first and last date in the database. */
      long[] firstAndLastDates = this.queryFirstAndLastDatesFromDatabase(
          conn);
      if (null != firstAndLastDates) {
        response.firstDateInDatabase = dateFormat.format(
            firstAndLastDates[0]);
        response.lastDateInDatabase = dateFormat.format(firstAndLastDates[1]);

        /* Consider all consensuses published on or within a day of the given
         * date. */
        long timestampFrom = timestamp - 24L * 60L * 60L * 1000L;
        long timestampTo = timestamp + 2 * 24L * 60L * 60L * 1000L - 1L;
        String fromValidAfter = validAfterTimeFormat.format(timestampFrom);
        String toValidAfter = validAfterTimeFormat.format(timestampTo);
        SortedSet<Long> relevantConsensuses =
            this.queryKnownConsensusValidAfterTimes(conn, fromValidAfter,
                toValidAfter);
        if (null != relevantConsensuses && !relevantConsensuses.isEmpty()) {
          response.relevantStatuses = true;

          /* Search for status entries with the given IP address as onion
           * routing address, plus status entries of relays having an exit
           * list entry with the given IP address as exit address. */
          List<QueryResponse.Match> matches = this.queryStatusEntries(conn,
              relayIp, timestamp, validAfterTimeFormat);
          if (!matches.isEmpty()) {
            response.matches = matches.toArray(new QueryResponse.Match[0]);

          /* If we didn't find anything, run another query to find out if
           * there are relays running on other IP addresses in the same /24 or
           * /48 network and tell the user about it. */
          } else {
            if (!relayIp.contains(":")) {
              String address24 = this.convertIpV4ToHex(relayIp)
                  .substring(0, 6);
              if (address24 != null) {
                response.nearbyAddresses = this.queryAddressesInSame24(conn,
                    address24, timestamp).toArray(new String[0]);
              }
            } else {
              String address48 = this.convertIpV6ToHex(relayIp)
                  .substring(0, 12);
              if (address48 != null) {
                response.nearbyAddresses = this.queryAddressesInSame48(conn,
                    address48, timestamp).toArray(new String[0]);
              }
            }
          }
        }
      }

      /* Close the database connection. */
      this.closeDatabaseConnection(conn, requestedConnection);
    }
    return response;
  }

  private Connection connectToDatabase() {
    Connection conn = null;
    try {
      conn = this.ds.getConnection();
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Couldn't connect: " + e.getMessage(), e);
    }
    return conn;
  }

  private long[] queryFirstAndLastDatesFromDatabase(Connection conn) {
    long[] firstAndLastDates = null;
    try {
      Statement statement = conn.createStatement();
      String query = "SELECT DATE(MIN(validafter)) AS first, "
          + "DATE(MAX(validafter)) AS last FROM statusentry";
      ResultSet rs = statement.executeQuery(query);
      if (rs.next()) {
        Calendar utcCalendar = Calendar.getInstance(
            TimeZone.getTimeZone("UTC"));
        firstAndLastDates = new long[] {
            rs.getTimestamp(1, utcCalendar).getTime(),
            rs.getTimestamp(2, utcCalendar).getTime()
        };
      }
      rs.close();
      statement.close();
    } catch (SQLException e) {
      /* Looks like we don't have any consensuses. */
      firstAndLastDates = null;
    }
    return firstAndLastDates;
  }

  private SortedSet<Long> queryKnownConsensusValidAfterTimes(
      Connection conn, String fromValidAfter, String toValidAfter) {
    SortedSet<Long> relevantConsensuses = new TreeSet<>();
    try {
      Statement statement = conn.createStatement();
      String query = "SELECT DISTINCT validafter FROM statusentry "
          + "WHERE validafter >= '" + fromValidAfter
          + "' AND validafter <= '" + toValidAfter + "'";
      ResultSet rs = statement.executeQuery(query);
      while (rs.next()) {
        long consensusTime = rs.getTimestamp(1).getTime();
        relevantConsensuses.add(consensusTime);
      }
      rs.close();
      statement.close();
    } catch (SQLException e) {
      /* Looks like we don't have any consensuses in the requested
       * interval. */
      relevantConsensuses = null;
    }
    return relevantConsensuses;
  }

  private List<QueryResponse.Match> queryStatusEntries(Connection conn,
      String relayIp, long timestamp,
      SimpleDateFormat validAfterTimeFormat) {
    List<QueryResponse.Match> matches = new ArrayList<>();
    String addressHex = !relayIp.contains(":")
        ? this.convertIpV4ToHex(relayIp) : this.convertIpV6ToHex(relayIp);
    if (addressHex == null) {
      return null;
    }
    String address24Or48Hex = !relayIp.contains(":")
        ? addressHex.substring(0, 6) : addressHex.substring(0, 12);
    try {
      CallableStatement cs;
      if (!relayIp.contains(":")) {
        cs = conn.prepareCall("{call search_by_address24_date(?, ?)}");
      } else {
        cs = conn.prepareCall("{call search_by_address48_date(?, ?)}");
      }
      cs.setString(1, address24Or48Hex);
      Calendar utcCalendar = Calendar.getInstance(
          TimeZone.getTimeZone("UTC"));
      cs.setDate(2, new java.sql.Date(timestamp), utcCalendar);
      ResultSet rs = cs.executeQuery();
      while (rs.next()) {
        byte[] rawstatusentry = rs.getBytes(1);
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
        if (!addressesHex.contains(addressHex)) {
          continue;
        }
        long validafter = rs.getTimestamp(2, utcCalendar).getTime();
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
      rs.close();
      cs.close();
    } catch (SQLException e) {
      /* Nothing found. */
      matches.clear();
    }
    return matches;
  }

  private List<String> queryAddressesInSame24(Connection conn,
      String address24, long timestamp) {
    List<String> addressesInSameNetwork = new ArrayList<>();
    try {
      CallableStatement cs = conn.prepareCall(
          "{call search_addresses_in_same_24 (?, ?)}");
      cs.setString(1, address24);
      cs.setDate(2, new java.sql.Date(timestamp));
      ResultSet rs = cs.executeQuery();
      while (rs.next()) {
        String address = rs.getString(1);
        if (!addressesInSameNetwork.contains(address)) {
          addressesInSameNetwork.add(address);
        }
      }
      rs.close();
      cs.close();
    } catch (SQLException e) {
      /* No other addresses in the same /24 found. */
      addressesInSameNetwork = null;
    }
    return addressesInSameNetwork;
  }

  private List<String> queryAddressesInSame48(Connection conn,
      String address48, long timestamp) {
    List<String> addressesInSameNetwork = new ArrayList<>();
    try {
      CallableStatement cs = conn.prepareCall(
          "{call search_addresses_in_same_48 (?, ?)}");
      cs.setString(1, address48);
      cs.setDate(2, new java.sql.Date(timestamp));
      ResultSet rs = cs.executeQuery();
      while (rs.next()) {
        String address = rs.getString(1);
        if (!addressesInSameNetwork.contains(address)) {
          addressesInSameNetwork.add(address);
        }
      }
      rs.close();
      cs.close();
    } catch (SQLException e) {
      /* No other addresses in the same /48 found. */
      addressesInSameNetwork = null;
    }
    return addressesInSameNetwork;
  }

  private void closeDatabaseConnection(Connection conn,
      long requestedConnection) {
    try {
      conn.close();
      this.logger.info("Returned a database connection to the pool "
          + "after " + (System.currentTimeMillis()
          - requestedConnection) + " millis.");
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Couldn't close: " + e.getMessage(), e);
    }
    return;
  }

}

