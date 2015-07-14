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
      this.writeSummaryUnableToConnectToDatabase(out);
      this.writeFooter(out);
      return;
    }

    /* Look up first and last date in the database. */
    long[] firstAndLastDates = this.queryFirstAndLastDatesFromDatabase(
        conn);
    if (firstAndLastDates == null) {
      this.writeSummaryNoData(out);
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
    }
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String firstDate = dateFormat.format(firstAndLastDates[0]);
    String lastDate = dateFormat.format(firstAndLastDates[1]);

    /* Parse parameters. */
    String ipParameter = request.getParameter("ip");
    String relayIP = this.parseIpParameter(ipParameter);
    boolean relayIPHasError = relayIP == null;

    /* Parse timestamp parameter. */
    String timestampParameter = request.getParameter("timestamp");
    String timestampStr = this.parseTimestampParameter(
        timestampParameter);
    boolean timestampHasError = timestampStr == null;

    /* Check that timestamp is within range. */
    long timestamp = 0L;
    boolean timestampOutOfRange = false;
    if (timestampStr != null && timestampStr.length() > 0) {
      try {
        timestamp = dateFormat.parse(timestampParameter).getTime();
        if (timestamp < firstAndLastDates[0] ||
            timestamp > firstAndLastDates[1]) {
          timestampOutOfRange = true;
        }
      } catch (ParseException e) {
        /* Already checked in parseTimestamp(). */
      }
    }

    /* Write form. */
    this.writeForm(out, relayIP, relayIPHasError ||
        ("".equals(relayIP) && !"".equals(timestampStr)), timestampStr,
        !relayIPHasError && (timestampHasError || timestampOutOfRange ||
        (!"".equals(relayIP) && "".equals(timestampStr))));

    /* If both parameters are empty, don't print any summary and exit.
     * This is the start page. */
    if ("".equals(relayIP) && "".equals(timestampStr)) {
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* If either parameter is empty, print summary with warning message
     * and exit. */
    if ("".equals(relayIP) || "".equals(timestampStr)) {
      if ("".equals(relayIP)) {
        writeSummaryNoIp(out);
      } else {
        writeSummaryNoTimestamp(out);
      }
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* If there's a user error, print summary with exit message and
     * exit. */
    if (relayIPHasError || timestampHasError || timestampOutOfRange) {
      if (relayIPHasError) {
        this.writeSummaryInvalidIp(out, ipParameter);
      } else if (timestampHasError) {
        this.writeSummaryInvalidTimestamp(out, timestampParameter);
      } else if (timestampOutOfRange) {
        this.writeSummaryTimestampOutsideRange(out, timestampStr,
            firstDate, lastDate);
      }
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* Consider all consensuses published on or within a day of the given
     * date. */
    long timestampFrom = timestamp - 24L * 60L * 60L * 1000L;
    long timestampTo = timestamp + 2 * 24L * 60L * 60L * 1000L - 1L;
    SimpleDateFormat validAfterTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    validAfterTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String fromValidAfter = validAfterTimeFormat.format(timestampFrom);
    String toValidAfter = validAfterTimeFormat.format(timestampTo);
    SortedSet<Long> relevantConsensuses =
        this.queryKnownConsensusValidAfterTimes(conn, fromValidAfter,
        toValidAfter);
    if (relevantConsensuses == null || relevantConsensuses.isEmpty()) {
      this.writeSummaryNoDataForThisInterval(out);
      this.writeFooter(out);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* Search for status entries with the given IP address as onion
     * routing address, plus status entries of relays having an exit list
     * entry with the given IP address as exit address. */
    List<String[]> statusEntries = this.queryStatusEntries(conn, relayIP,
        timestamp, validAfterTimeFormat);

    /* If we didn't find anything, run another query to find out if there
     * are relays running on other IP addresses in the same /24 or /48
     * network and tell the user about it. */
    List<String> addressesInSameNetwork = null;
    if (statusEntries.isEmpty()) {
      addressesInSameNetwork = new ArrayList<String>();
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
    }

    /* Print out result. */
    if (!statusEntries.isEmpty()) {
      this.writeSummaryPositive(out, relayIP, timestampStr);
      this.writeTechnicalDetails(out, relayIP, timestampStr,
          statusEntries);
    } else if (addressesInSameNetwork != null &&
        !addressesInSameNetwork.isEmpty()) {
      this.writeSummaryAddressesInSameNetwork(out, relayIP,
          timestampStr, addressesInSameNetwork);
    } else {
      this.writeSummaryNegative(out, relayIP, timestampStr);
    }

    this.writePermanentLink(out, relayIP, timestampStr);

    this.closeDatabaseConnection(conn, requestedConnection);
    this.writeFooter(out);
  }

  /* Helper methods for handling the request. */

  private String parseIpParameter(String ipParameter) {
    String relayIP = null;
    if (ipParameter != null && ipParameter.length() > 0) {
      Pattern ipv4AddressPattern = Pattern.compile(
          "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
          "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
          "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
          "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
      Pattern ipv6AddressPattern = Pattern.compile(
          "^\\[?[0-9a-fA-F:]{3,39}\\]?$");
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
      }
    } else {
      relayIP = "";
    }
    return relayIP;
  }

  private String parseTimestampParameter(String timestampParameter) {
    String timestampStr = "";
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    dateFormat.setLenient(false);
    if (timestampParameter != null && timestampParameter.length() > 0) {
      try {
        long timestamp = dateFormat.parse(timestampParameter).getTime();
        timestampStr = dateFormat.format(timestamp);
      } catch (ParseException e) {
        timestampStr = null;
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
    out.println("<!DOCTYPE html>\n"
        + "<html lang=\"en\">\n"
        + "<head>\n"
        + "<meta charset=\"utf-8\">\n"
        + "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n"
        + "<meta name=\"viewport\" content=\"width=device-width, "
          + "initial-scale=1\">\n"
        + "<title>ExoneraTor</title>\n"
        + "<link rel=\"stylesheet\" href=\"css/bootstrap.min.css\">\n"
        + "<link href=\"images/favicon.ico\" type=\"image/x-icon\" "
          + "rel=\"icon\">\n"
        + "</head>\n"
        + "<body>\n"
        + "<div class=\"container\">\n"
        + "<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<div class=\"page-header\">\n"
        + "<h1><a href=\"/\">ExoneraTor</a></h1>\n"
        + "</div><!-- page-header -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeForm(PrintWriter out, String relayIP,
      boolean relayIPHasError, String timestampStr,
      boolean timestampHasError) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<div class=\"text-center\">\n"
        + "<form class=\"form-inline\">\n"
        + "<div class=\"form-group%s\">\n"
        + "<label for=\"inputIp\" class=\"control-label\">IP "
          + "address</label>\n"
        + "<input type=\"text\" class=\"form-control\" name=\"ip\" "
          + "id=\"inputIp\" placeholder=\"86.59.21.38\"%s required>\n"
        + "</div><!-- form-group -->\n"
        + "<div class=\"form-group%s\">\n"
        + "<label for=\"inputTimestamp\" "
          + "class=\"control-label\">Date</label>\n"
        + "<input type=\"date\" class=\"form-control\" "
          + "name=\"timestamp\" id=\"inputTimestamp\" "
          + "placeholder=\"2010-01-01\"%s required>\n"
        + "</div><!-- form-group -->\n"
        + "<button type=\"submit\" "
          + "class=\"btn btn-primary\">Search</button>\n"
        + "</form>\n"
        + "</div><!-- text-center -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n",
        relayIPHasError ? " has-error" : "",
        relayIP != null && relayIP.length() > 0 ?
            " value=\"" + relayIP + "\"" : "",
        timestampHasError ? " has-error" : "",
        timestampStr != null && timestampStr.length() > 0 ?
            " value=\"" + timestampStr + "\"" : "");
  }

  private void writeSummaryUnableToConnectToDatabase(PrintWriter out)
      throws IOException {
    out.print("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Server problem</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "Unable to connect to the database.\n"
        + "Please try again later.\n"
        + "If this problem persists, please <a "
          + "href=\"https://www.torproject.org/about/contact\">let us "
          + "know</a>!\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeSummaryNoData(PrintWriter out) throws IOException {
    out.print("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Server problem</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "The database appears to be empty.\n"
        + "Please try again later.\n"
        + "If this problem persists, please <a "
          + "href=\"https://www.torproject.org/about/contact\">let us "
          + "know</a>!\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeSummaryNoTimestamp(PrintWriter out) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">No date parameter given</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "<p>Sorry, you also need to provide a date parameter.</p>\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeSummaryNoIp(PrintWriter out) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">No IP address parameter given</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "<p>Sorry, you also need to provide an IP address "
          + "parameter.</p>\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeSummaryTimestampOutsideRange(PrintWriter out,
      String timestampStr, String firstDate, String lastDate)
      throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Date parameter out of range</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "<p>Sorry, the database does not contain any data from %s.\n"
        + "Please pick a date between %s and %s.</p>\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n", timestampStr, firstDate, lastDate);
  }

  private void writeSummaryInvalidIp(PrintWriter out, String ipParameter)
      throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Invalid IP address parameter</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "<p>Sorry, \"%s\" is not a valid IP address.\n"
        + "The expected IP address formats are \"a.b.c.d\" or "
          + "\"[a:b:c::d]\".</p>\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n",
        ipParameter.length() > 40 ?
        StringEscapeUtils.escapeHtml(ipParameter.substring(0, 40))
        + "[...]" : StringEscapeUtils.escapeHtml(ipParameter));
  }

  private void writeSummaryInvalidTimestamp(PrintWriter out,
      String timestampParameter) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Invalid date parameter</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "<p>Sorry, \"%s\" is not a valid date.\n"
        + "The expected date format is \"YYYY-MM-DD\".\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n",
        timestampParameter.length() > 20 ?
        StringEscapeUtils.escapeHtml(timestampParameter.
        substring(0, 20)) + "[...]" :
        StringEscapeUtils.escapeHtml(timestampParameter));
  }

  private void writeSummaryNoDataForThisInterval(PrintWriter out)
      throws IOException {
    out.print("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-danger\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Server problem</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "The database does not contain any data for the requested "
          + "date.\n"
        + "Please try again later.\n"
        + "If this problem persists, please <a "
          + "href=\"https://www.torproject.org/about/contact\">let us "
          + "know</a>!\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeSummaryAddressesInSameNetwork(PrintWriter out,
      String relayIP, String timestampStr,
      List<String> addressesInSameNetwork) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-warning\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Result is negative</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "<p>We did not find IP address %s on or within a day of %s.\n"
        + "But we did find other IP addresses of Tor relays in the same "
          + "/%d network around the time:</p>\n"
        + "<ul>\n", relayIP, timestampStr,
        relayIP.contains(":") ? 48 : 24);
    for (String s : addressesInSameNetwork) {
      out.printf("<li><a href=\"/?ip=%s&timestamp=%s\">%s</a></li>\n",
          s.contains(":") ? "[" + s.replaceAll(":", "%3A") + "]" : s,
          timestampStr, s);
    }
    out.print("</ul>\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writeSummaryPositive(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-success\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Result is positive</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "We found one or more Tor relays on IP address %s on or within "
          + "a day of %s that Tor clients were likely to know.\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n", relayIP, timestampStr);
  }

  private void writeSummaryNegative(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Summary</h2>\n"
        + "<div class=\"panel panel-warning\">\n"
        + "<div class=\"panel-heading\">\n"
        + "<h3 class=\"panel-title\">Result is negative</h3>\n"
        + "</div><!-- panel-heading -->\n"
        + "<div class=\"panel-body\">\n"
        + "We did not find IP address %s on or within a day of %s.\n"
        + "</div><!-- panel-body -->\n"
        + "</div><!-- panel -->\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n", relayIP, timestampStr);
  }

  private void writeTechnicalDetails(PrintWriter out, String relayIP,
      String timestampStr, List<String[]> tableRows) throws IOException {
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Technical details</h2>\n"
        + "<p>Looking up IP address %s on or within one day of %s. Tor "
          + "clients could have selected this or these Tor relays to "
          + "build circuits.</p>\n"
        + "<table class=\"table\">\n"
        + "<thead>\n"
        + "<tr>\n"
        + "<th>Timestamp (UTC)</th>\n"
        + "<th>IP address(es)</th>\n"
        + "<th>Identity fingerprint</th>\n"
        + "<th>Nickname</th>\n"
        + "<th>Exit</th>\n"
        + "</tr>\n"
        + "</thead>\n"
        + "<tbody>\n", relayIP, timestampStr);
    for (String[] tableRow : tableRows) {
      out.print("<tr>");
      for (String tableColumn : tableRow) {
        out.print("<td>" + tableColumn + "</td>");
      }
      out.print("</tr>\n");
    }
    out.print("</tr>\n"
        + "</tbody>\n"
        + "</table>\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n");
  }

  private void writePermanentLink(PrintWriter out, String relayIP,
      String timestampStr) throws IOException {
    String encodedAddress = relayIP.contains(":") ?
        "[" + relayIP.replaceAll(":", "%3A") + "]" : relayIP;
    out.printf("<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<h2>Permanent link</h2>\n"
        + "<pre>https://exonerator.torproject.org/?ip=%s&amp;"
          + "timestamp=%s</pre>\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n", encodedAddress, timestampStr);
  }

  private void writeFooter(PrintWriter out) throws IOException {
    out.println("<div class=\"row\">\n"
        + "<div class=\"col-xs-6\">\n"
        + "<h3>About Tor</h3>\n"
        + "<p class=\"small\">\n"
        + "Tor anonymizes Internet traffic by <a "
          + "href=\"https://www.torproject.org/about/"
          + "overview#thesolution\">sending packets through a series of "
          + "encrypted hops before they reach their destination</a>.\n"
        + "Therefore, if you see traffic from a Tor relay, you may be "
          + "seeing traffic that originated from someone using Tor, "
          + "rather than from the relay operator.\n"
        + "The Tor Project and Tor relay operators have no records of "
          + "the traffic that passes over the network.\n"
        + "Be sure to <a "
          + "href=\"https://www.torproject.org/about/overview\">learn "
          + "more about Tor</a>, and don't hesitate to <a "
          + "href=\"https://www.torproject.org/about/contact\">contact "
          + "The Tor Project</a> for more information.\n"
        + "</p>\n"
        + "</div><!-- col -->\n"
        + "<div class=\"col-xs-6\">\n"
        + "<h3>About ExoneraTor</h3>\n"
        + "<p class=\"small\">\n"
        + "The ExoneraTor service maintains a database of IP addresses "
          + "that have been part of the Tor network.\n"
        + "It answers the question whether there was a Tor relay running "
          + "on a given IP address on a given date.\n"
        + "ExoneraTor may store more than one IP address per relay if "
          + "relays use a different IP address for exiting to the "
          + "Internet than for registering in the Tor network, and it "
          + "stores whether a relay permitted transit of Tor traffic to "
          + "the open Internet at that time.\n"
        + "</p>\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n"
        + "<div class=\"row\">\n"
        + "<div class=\"col-xs-12\">\n"
        + "<p class=\"text-center small\">\"Tor\" and the \"Onion Logo\" "
          + "are <a href=\"https://www.torproject.org/docs/"
          + "trademark-faq.html.en\">registered trademarks</a> of The "
          + "Tor Project, Inc.</p>\n"
        + "</div><!-- col -->\n"
        + "</div><!-- row -->\n"
        + "</div><!-- container -->\n"
        + "</body>\n"
        + "</html>\n");
    out.close();
  }
}

