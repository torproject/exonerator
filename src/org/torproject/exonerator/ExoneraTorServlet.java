/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.exonerator;

import java.io.IOException;
import java.io.PrintWriter;
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

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringEscapeUtils;

public class ExoneraTorServlet extends HttpServlet {

  private static final long serialVersionUID = 1370088989739567509L;

  private DataSource ds;

  private Logger logger;

  public void init() {

    /* Initialize logger. */
    this.logger = Logger.getLogger(ExoneraTorServlet.class.toString());

    /* Look up data source. */
    try {
      Context cxt = new InitialContext();
      this.ds = (DataSource) cxt.lookup("java:comp/env/jdbc/exonerator");
      this.logger.info("Successfully looked up data source.");
    } catch (NamingException e) {
      this.logger.log(Level.WARNING, "Could not look up data source", e);
    }
  }

  public void doGet(HttpServletRequest request,
      HttpServletResponse response) throws IOException,
      ServletException {

    /* Start writing response. */
    PrintWriter out = response.getWriter();
    this.writeHeader(out);

    /* Open a database connection that we'll use to handle the whole
     * request. */
    long requestedConnection = System.currentTimeMillis();
    Connection conn = this.connectToDatabase();
    if (conn == null) {
      this.writeUnableToConnectToDatabaseWarning(out);
      this.writeFooter(out);
      return;
    }

    /* Look up first and last date in the database. */
    long[] firstAndLastDates = this.queryFirstAndLastDatesFromDatabase(
        conn);
    if (firstAndLastDates == null) {
      this.writeNoDataWarning(out);
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
    }

    /* Parse IP parameter. */
    String ipParameter = request.getParameter("ip");
    StringBuilder ipWarningBuilder = new StringBuilder();
    String relayIP = this.parseIpParameter(ipParameter, ipWarningBuilder);

    /* Parse timestamp parameter. */
    String timestampParameter = request.getParameter("timestamp");
    StringBuilder timestampWarningBuilder = new StringBuilder();
    String timestampStr = this.parseTimestampParameter(timestampParameter,
        timestampWarningBuilder, firstAndLastDates);
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    long timestamp = 0L;
    if (timestampStr.length() > 0) {
      try {
        timestamp = dateFormat.parse(timestampParameter).getTime();
      } catch (ParseException e) {
        /* Already checked in parseTimestamp(). */
      }
    }

    /* If either IP address or timestamp is provided, the other one must
     * be provided, too. */
    if (relayIP.length() < 1 && timestampStr.length() > 0 &&
        ipWarningBuilder.length() < 1) {
      ipWarningBuilder.append("Please provide an IP address.");
    }
    if (relayIP.length() > 0 && timestamp < 1 &&
        timestampWarningBuilder.length() < 1) {
      timestampWarningBuilder.append("Please provide a date.");
    }

    /* Write form with IP address and timestamp. */
    this.writeForm(out, relayIP, ipWarningBuilder.toString(),
        timestampStr, timestampWarningBuilder.toString());

    if (relayIP.length() < 1 || timestamp < 1L) {
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* Consider all consensuses published on or within a day of the given
     * date. */
    long timestampFrom = timestamp - 24L * 60L * 60L * 1000L;
    long timestampTo = timestamp + 2 * 24L * 60L * 60L * 1000L - 1L;
    this.writeSearchInfos(out, relayIP, timestampStr);
    SimpleDateFormat validAfterTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    validAfterTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String fromValidAfter = validAfterTimeFormat.format(timestampFrom);
    String toValidAfter = validAfterTimeFormat.format(timestampTo);
    SortedSet<Long> relevantConsensuses =
        this.queryKnownConsensusValidAfterTimes(conn, fromValidAfter,
        toValidAfter);
    if (relevantConsensuses == null || relevantConsensuses.isEmpty()) {
      this.writeNoDataForThisInterval(out, relayIP, timestampStr);
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* Search for status entries with the given IP address as onion
     * routing address, plus status entries of relays having an exit list
     * entry with the given IP address as exit address. */
    List<String[]> statusEntries = this.queryStatusEntries(conn, relayIP,
        timestamp, validAfterTimeFormat);

    /* Print out what we found. */
    if (!statusEntries.isEmpty()) {
      this.writeResultsTable(out, statusEntries);
    } else {
      /* Run another query to find out if there are relays running on
       * other IP addresses in the same /24 or /48 network and tell the
       * user about it. */
      List<String> addressesInSameNetwork = new ArrayList<String>();
      if (!relayIP.contains(":")) {
        String[] relayIPParts = relayIP.split("\\.");
        byte[] address24Bytes = new byte[3];
        address24Bytes[0] = (byte) Integer.parseInt(relayIPParts[0]);
        address24Bytes[1] = (byte) Integer.parseInt(relayIPParts[1]);
        address24Bytes[2] = (byte) Integer.parseInt(relayIPParts[2]);
        String address24 = Hex.encodeHexString(address24Bytes);
        addressesInSameNetwork = this.queryAddressesInSame24(conn,
            address24, timestamp);
      } else {
        StringBuilder addressHex = new StringBuilder();
        int start = relayIP.startsWith("::") ? 1 : 0;
        int end = relayIP.length() - (relayIP.endsWith("::") ? 1 : 0);
        String[] parts = relayIP.substring(start, end).split(":", -1);
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
          if (!addressHexString.contains("x") &&
              addressHexString.length() == 32) {
            address48 = addressHexString.replaceAll(" ", "0").
                toLowerCase().substring(0, 12);
          }
        }
        if (address48 != null) {
          addressesInSameNetwork = this.queryAddressesInSame48(conn,
              address48, timestamp);
        }
      }
      if (addressesInSameNetwork == null ||
          addressesInSameNetwork.isEmpty()) {
        this.writeNoneFound(out, relayIP, timestampStr);
      } else {
        this.writeAddressesInSameNetwork(out, relayIP, timestampStr,
            addressesInSameNetwork);
      }
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* Print out result. */
    if (!statusEntries.isEmpty()) {
      this.writeSummaryPositive(out, relayIP, timestampStr);
    } else {
      this.writeSummaryNegative(out, relayIP, timestampStr);
    }

    this.closeDatabaseConnection(conn, requestedConnection);
    this.writeFooter(out);
  }

  /* Helper methods for handling the request. */

  private String parseIpParameter(String ipParameter,
      StringBuilder ipWarningBuilder) {
    String relayIP = "";
    Pattern ipv4AddressPattern = Pattern.compile(
        "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
    Pattern ipv6AddressPattern = Pattern.compile(
        "^\\[?[0-9a-fA-F:]{3,39}\\]?$");
    if (ipParameter != null && ipParameter.length() > 0) {
      if (ipv4AddressPattern.matcher(ipParameter).matches()) {
        String[] ipParts = ipParameter.split("\\.");
        relayIP = Integer.parseInt(ipParts[0]) + "."
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
          if (!addressHexString.contains("x") &&
              addressHexString.length() == 32) {
            relayIP = ipParameter.toLowerCase();
          }
        }
        if (relayIP.length() < 1) {
          ipWarningBuilder.append("\"" + (ipParameter.length() > 40 ?
              StringEscapeUtils.escapeHtml(ipParameter.substring(0, 40))
              + "[...]" : StringEscapeUtils.escapeHtml(ipParameter))
              + "\" is not a valid IP address.");
        }
      } else {
        ipWarningBuilder.append("\"" + (ipParameter.length() > 20 ?
            StringEscapeUtils.escapeHtml(ipParameter.substring(0, 20))
            + "[...]" : StringEscapeUtils.escapeHtml(ipParameter))
            + "\" is not a valid IP address.");
      }
    }
    return relayIP;
  }

  private String parseTimestampParameter(String timestampParameter,
      StringBuilder timestampWarningBuilder, long[] firstAndLastDates) {
    String timestampStr = "";
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    if (timestampParameter != null && timestampParameter.length() > 0) {
      try {
        long timestamp = dateFormat.parse(timestampParameter).getTime();
        timestampStr = dateFormat.format(timestamp);
        if (timestamp < firstAndLastDates[0] ||
            timestamp > firstAndLastDates[1]) {
          timestampWarningBuilder.append("Please pick a date between \""
              + dateFormat.format(firstAndLastDates[0]) + "\" and \""
              + dateFormat.format(firstAndLastDates[1]) + "\".");
        }
      } catch (ParseException e) {
        /* We have no way to handle this exception, other than leaving
           timestampStr at "". */
        timestampWarningBuilder.append("\""
            + (timestampParameter.length() > 20 ?
            StringEscapeUtils.escapeHtml(timestampParameter.
            substring(0, 20)) + "[...]" :
            StringEscapeUtils.escapeHtml(timestampParameter))
            + "\" is not a valid date.");
      }
    }
    return timestampStr;
  }

  /* Helper methods for querying the database. */

  private Connection connectToDatabase() {
    Connection conn = null;
    try {
      conn = this.ds.getConnection();
    } catch (SQLException e) {
    }
    return conn;
  }

  private long[] queryFirstAndLastDatesFromDatabase(Connection conn) {
    long[] firstAndLastDates = null;
    try {
      Statement statement = conn.createStatement();
      String query = "SELECT DATE(MIN(validafter)) AS first, "
          + "DATE(MAX(validafter)) AS last FROM consensus";
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
    SortedSet<Long> relevantConsensuses = new TreeSet<Long>();
    try {
      Statement statement = conn.createStatement();
      String query = "SELECT validafter FROM consensus "
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

  private List<String[]> queryStatusEntries(Connection conn,
      String relayIP, long timestamp,
      SimpleDateFormat validAfterTimeFormat) {
    List<String[]> statusEntries = new ArrayList<String[]>();
    try {
      CallableStatement cs = conn.prepareCall(
          "{call search_statusentries_by_address_date(?, ?)}");
      cs.setString(1, relayIP);
      Calendar utcCalendar = Calendar.getInstance(
          TimeZone.getTimeZone("UTC"));
      cs.setDate(2, new java.sql.Date(timestamp), utcCalendar);
      ResultSet rs = cs.executeQuery();
      while (rs.next()) {
        byte[] rawstatusentry = rs.getBytes(1);
        SortedSet<String> addresses = new TreeSet<String>();
        long validafter = rs.getTimestamp(3, utcCalendar).getTime();
        String validAfterString = validAfterTimeFormat.format(validafter);
        String fingerprint = rs.getString(4).toUpperCase();
        String nickname = "(Unknown)";
        String exit = "Unknown";
        for (String line : new String(rawstatusentry).split("\n")) {
          if (line.startsWith("r ")) {
            String[] parts = line.split(" ");
            nickname = parts[1];
            addresses.add(parts[6]);
          } else if (line.startsWith("a ")) {
            String address = line.substring("a ".length(),
                line.lastIndexOf(":"));
            addresses.add(address);
          } else if (line.startsWith("p ")) {
            exit = line.equals("p reject 1-65535") ? "No" : "Yes";
          }
        }
        String exitaddress = rs.getString(6);
        if (exitaddress != null && exitaddress.length() > 0) {
          addresses.add(exitaddress);
        }
        StringBuilder sb = new StringBuilder();
        int writtenAddresses = 0;
        for (String address : addresses) {
          sb.append((writtenAddresses++ > 0 ? ", " : "") + address);
        }
        String[] statusEntry = new String[] { validAfterString,
            sb.toString(), fingerprint, nickname, exit };
        statusEntries.add(statusEntry);
      }
      rs.close();
      cs.close();
    } catch (SQLException e) {
      /* Nothing found. */
      statusEntries = null;
    }
    return statusEntries;
  }

  private List<String> queryAddressesInSame24(Connection conn,
      String address24, long timestamp) {
    List<String> addressesInSameNetwork = new ArrayList<String>();
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
    List<String> addressesInSameNetwork = new ArrayList<String>();
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
    }
    return;
  }

  /* Helper methods for writing the response. */

  private void writeHeader(PrintWriter out) throws IOException {
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 "
          + "Transitional//EN\">\n"
        + "<html>\n"
        + "  <head>\n"
        + "    <title>ExoneraTor</title>\n"
        + "    <meta http-equiv=\"content-type\" content=\"text/html; "
          + "charset=ISO-8859-1\">\n"
        + "    <link href=\"/css/stylesheet-ltr.css\" type=\"text/css\" "
          + "rel=\"stylesheet\">\n"
        + "    <link href=\"/images/favicon.ico\" "
          + "type=\"image/x-icon\" rel=\"shortcut icon\">\n"
        + "  </head>\n"
        + "  <body>\n"
        + "    <div class=\"center\">\n"
        + "      <div class=\"main-column\" style=\"margin:5; "
          + "Padding:0;\">\n"
        + "        <h2>ExoneraTor</h2>\n"
        + "        <h3>or: a website that tells you whether a given IP "
          + "address was a Tor relay</h3>\n"
        + "        <br>\n"
        + "        <p>Just because you see an Internet connection from a "
          + "particular IP address does not mean you know <i>who</i> "
          + "originated the traffic. Tor anonymizes Internet traffic by "
          + "\"<a href=\"https://www.torproject.org/about/overview"
          + "#thesolution\">onion routing</a>,\" sending packets "
          + "through a series of encrypted hops before they reach their "
          + "destination. Therefore, if you see traffic from a Tor node, "
          + "you may be seeing traffic that originated from someone "
          + "using Tor, rather than from the node operator itself. The "
          + "Tor Project and Tor node operators have no records of the "
          + "traffic that passes over the network, but we do maintain "
          + "current and historical records of which IP addresses are "
          + "part of the Tor network.</p>\n"
        + "        <br>\n"
        + "        <p>ExoneraTor tells you whether there was a Tor relay "
          + "running on a given IP address at a given time. ExoneraTor "
          + "learns these facts by parsing the public relay lists that "
          + "are collected from the Tor directory authorities and the "
          + "exit lists collected by TorDNSEL. By inputting an IP "
          + "address and time, you can determine whether that IP was "
          + "then a part of the Tor network.</p>\n"
        + "        <br>\n"
        + "        <p><font color=\"red\"><b>Notice:</b> Note that the "
          + "information you are providing below may be visible to "
          + "anyone who can read the network traffic between you and "
          + "this web server or who has access to this web "
          + "server.</font></p>\n"
        + "        <br>\n");
  }

  private void writeUnableToConnectToDatabaseWarning(PrintWriter out)
      throws IOException {
    out.println("<p><font color=\"red\"><b>Warning: </b></font>Unable "
        + "to connect to the database. If this problem persists, "
        + "please <a href=\"mailto:tor-assistants@torproject.org\">let "
        + "us know</a>!</p>\n");
  }

  private void writeNoDataWarning(PrintWriter out) throws IOException {
    out.println("<p><font color=\"red\"><b>Warning: </b></font>This "
        + "server doesn't have any relay lists available. If this "
        + "problem persists, please "
        + "<a href=\"mailto:tor-assistants@lists.torproject.org\">let "
        + "us know</a>!</p>\n");
  }

  private void writeForm(PrintWriter out, String relayIP,
      String ipWarning, String timestampStr, String timestampWarning)
      throws IOException {
    out.println("<a name=\"relay\"></a><h3>Was there a Tor relay running "
        + "on this IP address?</h3>");
    out.println("        <form action=\"#relay\">\n"
        + "          <table>\n"
        + "            <tr>\n"
        + "              <td align=\"right\">IP address in question:"
          + "</td>\n"
        + "              <td><input type=\"text\" name=\"ip\" size=\"30\""
          + (relayIP.length() > 0 ? " value=\"" + relayIP + "\""
            : "")
          + ">"
          + (ipWarning.length() > 0 ? "<br><font color=\"red\">"
          + ipWarning + "</font>" : "")
        + "</td>\n"
        + "              <td><i>(Ex.: 86.59.21.38 or "
          + "2001:858:2:2:aabb:0:563b:1526)</i></td>\n"
        + "            </tr>\n"
        + "            <tr>\n"
        + "              <td align=\"right\">Date:</td>\n"
        + "              <td><input type=\"text\" name=\"timestamp\""
          + " size=\"30\""
          + (timestampStr.length() > 0 ? " value=\"" + timestampStr + "\""
            : "")
          + ">"
          + (timestampWarning.length() > 0 ? "<br><font color=\"red\">"
              + timestampWarning + "</font>" : "")
        + "</td>\n"
        + "              <td><i>(Ex.: 2010-01-01)"
          + "</i></td>\n"
        + "            </tr>\n"
        + "            <tr>\n"
        + "              <td></td>\n"
        + "              <td>\n"
        + "                <input type=\"submit\">\n"
        + "                <input type=\"reset\">\n"
        + "              </td>\n"
        + "              <td></td>\n"
        + "            </tr>\n"
        + "          </table>\n"
        + "        </form>\n");
  }

  private void writeSearchInfos(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.printf("<p>Looking up IP address %s in the relay lists "
        + "published ", relayIP);
    out.printf("on or within a day of %s", timestampStr);
    out.print(" as well as in the relevant exit lists. Clients could "
        + "have selected any of these relays to build circuits. "
        + "You may follow the links to relay lists and relay descriptors "
        + "to grep for the lines printed below and confirm that results "
        + "are correct.<br>\n");
  }

  private void writeNoDataForThisInterval(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.println("        <p>No relay lists found!</p>\n"
        + "        <p>Result is INDECISIVE!</p>\n"
        + "        <p>We cannot make any statement whether there was "
        + "a Tor relay running on IP address " + relayIP + " on "
        + timestampStr + "! We "
        + "did not find any relevant relay lists on or within a day of "
        + "the given date. If "
        + "you think this is an error on our side, please "
        + "<a href=\"mailto:tor-assistants@torproject.org\">contact "
        + "us</a>!</p>\n");
  }

  private void writeResultsTable(PrintWriter out,
      List<String[]> tableRows) throws IOException {
    out.print("<br>\n");
    out.print("<table>\n");
    out.print("<thead>\n");
    out.print("<tr><th>Timestamp (UTC)</th><th>IP address(es)</th>"
        + "<th>Identity fingerprint</th><th>Nickname</th><th>Exit</th>"
        + "</tr>\n");
    out.print("</thead>\n");
    out.print("<tbody>\n");
    for (String[] tableRow : tableRows) {
      out.print("<tr>");
      for (String tableColumn : tableRow) {
        out.print("<td>" + tableColumn + "</td>");
      }
      out.print("</tr>\n");
    }
    out.print("</tbody>\n");
    out.print("</table>\n");
  }

  private void writeNoneFound(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.printf("        <p>None found!</p>\n"
        + "        <p>Result is NEGATIVE with high certainty!</p>\n"
        + "        <p>We did not find IP "
        + "address " + relayIP + " in any of the relay or exit lists "
        + "that were published on or within a day of %s.</p>\n",
        timestampStr);
  }

  private void writeAddressesInSameNetwork(PrintWriter out,
      String relayIP, String timestampStr,
      List<String> addressesInSameNetwork) throws IOException {
    out.printf("        <p>None found!</p>\n"
        + "        <p>Result is NEGATIVE with high certainty!</p>\n"
        + "        <p>We did not find IP "
        + "address " + relayIP + " in any of the relay or exit lists "
        + "that were published on or within a day of %s.</p>\n",
        timestampStr);
    if (!relayIP.contains(":")) {
      out.print("        <p>The following other IP addresses of Tor "
          + "relays in the same /24 network were found in relay "
          + "and/or exit lists on or within a day of " + timestampStr
          + " that could be related "
          + "to IP address " + relayIP + ":</p>\n");
    } else {
      out.print("        <p>The following other IP addresses of Tor "
          + "relays in the same /48 network were found in relay "
          + "lists on or within a day of " + timestampStr
          + " that could be related to IP "
          + "address " + relayIP + ":</p>\n");
    }
    out.print("        <ul>\n");
    for (String s : addressesInSameNetwork) {
      out.print("        <li>" + s + "</li>\n");
    }
    out.print("        </ul>\n");
  }

  private void writeSummaryPositive(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.print("        <p>Result is POSITIVE with high certainty!"
        + "</p>\n"
        + "        <p>We found one or more relays on IP address "
        + relayIP + " in a ");
    out.print("relay list published on or within a day of "
        + timestampStr);
    out.print(" that clients were likely to know.</p>\n");
  }

  private void writeSummaryNegative(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.println("        <p>Result is NEGATIVE "
        + "with high certainty!</p>\n");
    out.println("        <p>We did not find any relay on IP address "
        + relayIP
        + " in the relay lists on or within a day of " + timestampStr
        + ".</p>\n");
  }

  private void writeFooter(PrintWriter out) throws IOException {
    out.println("        <br>\n"
        + "      </div>\n"
        + "    </div>\n"
        + "    <div class=\"bottom\" id=\"bottom\">\n"
        + "      <p>\"Tor\" and the \"Onion Logo\" are <a "
          + "href=\"https://www.torproject.org/docs/trademark-faq.html.en"
          + "\">registered trademarks</a> of The Tor Project, Inc.</p>\n"
        + "    </div>\n"
        + "  </body>\n"
        + "</html>");
    out.close();
  }
}

