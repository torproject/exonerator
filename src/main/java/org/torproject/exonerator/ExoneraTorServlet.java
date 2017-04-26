/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.exonerator;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringEscapeUtils;

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
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeMap;
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

public class ExoneraTorServlet extends HttpServlet {

  private static final long serialVersionUID = 1370088989739567509L;

  private DataSource ds;

  private Logger logger;

  private List<String> availableLanguages =
      Arrays.asList("de", "en", "fr", "ro", "sv");

  private SortedMap<String, String> availableLanguageNames;

  @Override
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

    this.availableLanguageNames = new TreeMap<>();
    for (String locale : this.availableLanguages) {
      ResourceBundle rb = ResourceBundle.getBundle("ExoneraTor",
          Locale.forLanguageTag(locale));
      this.availableLanguageNames.put(locale, rb.getString(
          "footer.language.name"));
    }
  }

  @Override
  public void doGet(HttpServletRequest request,
      HttpServletResponse response) throws IOException,
      ServletException {

    /* Set content type, or the page doesn't render in Chrome. */
    response.setContentType("text/html");
    response.setCharacterEncoding("utf-8");

    /* Find the right resource bundle for the user's requested language. */
    String langParameter = request.getParameter("lang");
    String langStr = "en";
    if (null != langParameter
        && this.availableLanguages.contains(langParameter)) {
      langStr = langParameter;
    }
    ResourceBundle rb = ResourceBundle.getBundle("ExoneraTor",
        Locale.forLanguageTag(langStr));

    /* Start writing response. */
    PrintWriter out = response.getWriter();
    this.writeHeader(out, rb, langStr);

    /* Open a database connection that we'll use to handle the whole
     * request. */
    long requestedConnection = System.currentTimeMillis();
    Connection conn = this.connectToDatabase();
    if (conn == null) {
      this.writeSummaryUnableToConnectToDatabase(out, rb);
      this.writeFooter(out, rb, null, null);
      return;
    }

    /* Look up first and last date in the database. */
    long[] firstAndLastDates = this.queryFirstAndLastDatesFromDatabase(
        conn);
    if (firstAndLastDates == null) {
      this.writeSummaryNoData(out, rb);
      this.writeFooter(out, rb, null, null);
      this.closeDatabaseConnection(conn, requestedConnection);
    }
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String firstDate = dateFormat.format(firstAndLastDates[0]);
    String lastDate = dateFormat.format(firstAndLastDates[1]);

    /* Parse parameters. */
    String ipParameter = request.getParameter("ip");
    String relayIp = this.parseIpParameter(ipParameter);
    boolean relayIpHasError = relayIp == null;

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
        if (timestamp < firstAndLastDates[0]
            || timestamp > firstAndLastDates[1]) {
          timestampOutOfRange = true;
        }
      } catch (ParseException e) {
        /* Already checked in parseTimestamp(). */
      }
    }

    /* Write form. */
    this.writeForm(out, rb, relayIp, relayIpHasError
        || ("".equals(relayIp) && !"".equals(timestampStr)), timestampStr,
        !relayIpHasError
        && !("".equals(relayIp) && !"".equals(timestampStr))
        && (timestampHasError || timestampOutOfRange
        || (!"".equals(relayIp) && "".equals(timestampStr))), langStr);

    /* If both parameters are empty, don't print any summary and exit.
     * This is the start page. */
    if ("".equals(relayIp) && "".equals(timestampStr)) {
      this.writeFooter(out, rb, null, null);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* If either parameter is empty, print summary with warning message
     * and exit. */
    if ("".equals(relayIp) || "".equals(timestampStr)) {
      if ("".equals(relayIp)) {
        writeSummaryNoIp(out, rb);
      } else {
        writeSummaryNoTimestamp(out, rb);
      }
      this.writeFooter(out, rb, null, null);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* If there's a user error, print summary with exit message and
     * exit. */
    if (relayIpHasError || timestampHasError || timestampOutOfRange) {
      if (relayIpHasError) {
        this.writeSummaryInvalidIp(out, rb, ipParameter);
      } else if (timestampHasError) {
        this.writeSummaryInvalidTimestamp(out, rb, timestampParameter);
      } else if (timestampOutOfRange) {
        this.writeSummaryTimestampOutsideRange(out, rb, timestampStr,
            firstDate, lastDate);
      }
      this.writeFooter(out, rb, relayIp, timestampStr);
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
      this.writeSummaryNoDataForThisInterval(out, rb);
      this.writeFooter(out, rb, relayIp, timestampStr);
      this.closeDatabaseConnection(conn, requestedConnection);
      return;
    }

    /* Search for status entries with the given IP address as onion
     * routing address, plus status entries of relays having an exit list
     * entry with the given IP address as exit address. */
    List<String[]> statusEntries = this.queryStatusEntries(conn, relayIp,
        timestamp, validAfterTimeFormat);

    /* If we didn't find anything, run another query to find out if there
     * are relays running on other IP addresses in the same /24 or /48
     * network and tell the user about it. */
    List<String> addressesInSameNetwork = null;
    if (statusEntries.isEmpty()) {
      addressesInSameNetwork = new ArrayList<>();
      if (!relayIp.contains(":")) {
        String address24 = this.convertIpV4ToHex(relayIp).substring(0, 6);
        if (address24 != null) {
          addressesInSameNetwork = this.queryAddressesInSame24(conn,
              address24, timestamp);
        }
      } else {
        String address48 = this.convertIpV6ToHex(relayIp).substring(
            0, 12);
        if (address48 != null) {
          addressesInSameNetwork = this.queryAddressesInSame48(conn,
              address48, timestamp);
        }
      }
    }

    /* Print out result. */
    if (!statusEntries.isEmpty()) {
      this.writeSummaryPositive(out, rb, relayIp, timestampStr);
      this.writeTechnicalDetails(out, rb, relayIp, timestampStr,
          statusEntries);
    } else if (addressesInSameNetwork != null
        && !addressesInSameNetwork.isEmpty()) {
      this.writeSummaryAddressesInSameNetwork(out, rb, relayIp,
          timestampStr, langStr, addressesInSameNetwork);
    } else {
      this.writeSummaryNegative(out, rb, relayIp, timestampStr);
    }

    this.writePermanentLink(out, rb, relayIp, timestampStr, langStr);

    this.closeDatabaseConnection(conn, requestedConnection);
    this.writeFooter(out, rb, relayIp, timestampStr);
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

  private String parseTimestampParameter(
      String passedTimestampParameter) {
    String timestampStr = "";
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    dateFormat.setLenient(false);
    if (passedTimestampParameter != null
        && passedTimestampParameter.length() > 0) {
      String timestampParameter = passedTimestampParameter.trim();
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

  private List<String[]> queryStatusEntries(Connection conn,
      String relayIp, long timestamp,
      SimpleDateFormat validAfterTimeFormat) {
    List<String[]> statusEntries = new ArrayList<>();
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
        String exit = "U";
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
            exit = line.equals("p reject 1-65535") ? "N" : "Y";
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
        StringBuilder sb = new StringBuilder();
        int writtenAddresses = 0;
        for (String address : addresses) {
          sb.append((writtenAddresses++ > 0 ? ", " : "") + address);
        }
        long validafter = rs.getTimestamp(2, utcCalendar).getTime();
        String validAfterString = validAfterTimeFormat.format(validafter);
        String fingerprint = rs.getString(3).toUpperCase();
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

  /* Helper methods for writing the response. */

  private void writeHeader(PrintWriter out, ResourceBundle rb, String langStr)
      throws IOException {
    out.printf("<!DOCTYPE html>\n"
        + "<html lang=\"%s\">\n"
        + "  <head>\n"
        + "    <meta charset=\"utf-8\">\n"
        + "    <meta http-equiv=\"X-UA-Compatible\" "
          + "content=\"IE=edge\">\n"
        + "    <meta name=\"viewport\" content=\"width=device-width, "
          + "initial-scale=1\">\n"
        + "    <title>ExoneraTor</title>\n"
        + "    <link rel=\"stylesheet\" href=\"css/bootstrap.min.css\">\n"
        + "    <link rel=\"stylesheet\" href=\"css/exonerator.css\">\n"
        + "    <link href=\"images/favicon.ico\" type=\"image/x-icon\" "
          + "rel=\"icon\">\n"
        + "  </head>\n"
        + "  <body>\n"
        + "    <div class=\"container\">\n"
        + "      <div class=\"row\">\n"
        + "        <div class=\"col-xs-12\">\n"
        + "          <div class=\"page-header\">\n"
        + "            <h1>\n"
        + "              <div class=\"text-center\">\n"
        + "                <a href=\"/?lang=%<s\">"
          + "<img src=\"images/exonerator-logo.png\" "
          + "width=\"334\" height=\"252\" alt=\"ExoneraTor logo\">"
          + "<img src=\"images/exonerator-wordmark.png\" width=\"428\" "
          + "height=\"63\" alt=\"ExoneraTor wordmark\"></a>\n"
        + "              </div><!-- text-center -->\n"
        + "            </h1>\n"
        + "          </div><!-- page-header -->\n"
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n",
        langStr);
  }

  private void writeForm(PrintWriter out, ResourceBundle rb,
      String relayIp, boolean relayIpHasError, String timestampStr,
      boolean timestampHasError, String langStr) throws IOException {
    String ipValue = "";
    if (relayIp != null && relayIp.length() > 0) {
      if (relayIp.contains(":")) {
        ipValue = String.format(" value=\"[%s]\"", relayIp);
      } else {
        ipValue = String.format(" value=\"%s\"", relayIp);
      }
    }
    out.printf("      <div class=\"row\">\n"
        + "        <div class=\"col-xs-12\">\n"
        + "          <div class=\"text-center\">\n"
        + "            <div class=\"row vbottom15\">\n"
        + "              <h4>%s</h4>\n"
        + "            </div> <!-- row -->\n"
        + "            <form class=\"form-inline\">\n"
        + "              <div class=\"form-group%s\">\n"
        + "                <label for=\"inputIp\" "
          + "class=\"control-label\">%s</label>\n"
        + "                <input type=\"text\" class=\"form-control\" "
          + "name=\"ip\" id=\"inputIp\" placeholder=\"86.59.21.38\"%s "
          + "required>\n"
        + "              </div><!-- form-group -->\n"
        + "              <div class=\"form-group%s\">\n"
        + "                <label for=\"inputTimestamp\" "
          + "class=\"control-label\">%s</label>\n"
        + "                <input type=\"date\" class=\"form-control\" "
          + "name=\"timestamp\" id=\"inputTimestamp\" "
          + "placeholder=\"2010-01-01\"%s required>\n"
        + "              </div><!-- form-group -->\n"
        + "              <input type=\"hidden\" name=\"lang\" value=\"%s\">\n"
        + "              <button type=\"submit\" "
          + "class=\"btn btn-primary\">%s</button>\n"
        + "            </form>\n"
        + "          </div><!-- text-center -->\n"
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n",
        rb.getString("form.explanation"),
        relayIpHasError ? " has-error" : "",
        rb.getString("form.ip.label"),
        ipValue,
        timestampHasError ? " has-error" : "",
        rb.getString("form.timestamp.label"),
        timestampStr != null && timestampStr.length() > 0
            ? " value=\"" + timestampStr + "\"" : "",
        langStr,
        rb.getString("form.search.label"));
  }

  private void writeSummaryUnableToConnectToDatabase(PrintWriter out,
      ResourceBundle rb) throws IOException {
    String contactLink =
        "<a href=\"https://www.torproject.org/about/contact\">"
        + rb.getString("summary.serverproblem.dbempty.body.link")
        + "</a>";
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.serverproblem.dbnoconnect.title"), null,
        rb.getString("summary.serverproblem.dbnoconnect.body.text"),
        contactLink);
  }

  private void writeSummaryNoData(PrintWriter out, ResourceBundle rb)
      throws IOException {
    String contactLink =
        "<a href=\"https://www.torproject.org/about/contact\">"
        + rb.getString("summary.serverproblem.dbempty.body.link")
        + "</a>";
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.serverproblem.dbempty.title"), null,
        rb.getString("summary.serverproblem.dbempty.body.text"),
        contactLink);
  }

  private void writeSummaryNoTimestamp(PrintWriter out, ResourceBundle rb)
      throws IOException {
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.invalidparams.notimestamp.title"), null,
        rb.getString("summary.invalidparams.notimestamp.body"));
  }

  private void writeSummaryNoIp(PrintWriter out, ResourceBundle rb)
      throws IOException {
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger", rb.getString("summary.invalidparams.noip.title"),
        null, rb.getString("summary.invalidparams.noip.body"));
  }

  private void writeSummaryTimestampOutsideRange(PrintWriter out,
      ResourceBundle rb, String timestampStr, String firstDate,
      String lastDate) throws IOException {
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.invalidparams.timestamprange.title"), null,
        rb.getString("summary.invalidparams.timestamprange.body"),
        timestampStr, firstDate, lastDate);
  }

  private void writeSummaryInvalidIp(PrintWriter out, ResourceBundle rb,
      String ipParameter) throws IOException {
    String escapedIpParameter = ipParameter.length() > 40
        ? StringEscapeUtils.escapeHtml(ipParameter.substring(0, 40))
        + "[...]" : StringEscapeUtils.escapeHtml(ipParameter);
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.invalidparams.invalidip.title"), null,
        rb.getString("summary.invalidparams.invalidip.body"),
        escapedIpParameter, "\"a.b.c.d\"", "\"[a:b:c:d:e:f:g:h]\"");
  }

  private void writeSummaryInvalidTimestamp(PrintWriter out,
      ResourceBundle rb, String timestampParameter) throws IOException {
    String escapedTimestampParameter = timestampParameter.length() > 20
        ? StringEscapeUtils.escapeHtml(timestampParameter
        .substring(0, 20)) + "[...]"
        : StringEscapeUtils.escapeHtml(timestampParameter);
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.invalidparams.invalidtimestamp.title"),
        null, rb.getString("summary.invalidparams.invalidtimestamp.body"),
        escapedTimestampParameter, "\"YYYY-MM-DD\"");
  }

  private void writeSummaryNoDataForThisInterval(PrintWriter out,
      ResourceBundle rb) throws IOException {
    String contactLink =
        "<a href=\"https://www.torproject.org/about/contact\">"
        + rb.getString("summary.serverproblem.dbempty.body.link")
        + "</a>";
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.serverproblem.nodata.title"), null,
        rb.getString("summary.serverproblem.nodata.body.text"),
        contactLink);
  }

  private void writeSummaryAddressesInSameNetwork(PrintWriter out,
      ResourceBundle rb, String relayIp, String timestampStr, String langStr,
      List<String> addressesInSameNetwork) throws IOException {
    Object[][] panelItems = new Object[addressesInSameNetwork.size()][];
    for (int i = 0; i < addressesInSameNetwork.size(); i++) {
      String addressInSameNetwork = addressesInSameNetwork.get(i);
      String link;
      String address;
      if (addressInSameNetwork.contains(":")) {
        link = String.format("/?ip=[%s]&timestamp=%s&lang=%s",
            addressInSameNetwork.replaceAll(":", "%3A"), timestampStr,
            langStr);
        address = "[" + addressInSameNetwork + "]";
      } else {
        link = String.format("/?ip=%s&timestamp=%s&lang=%s",
            addressInSameNetwork, timestampStr, langStr);
        address = addressInSameNetwork;
      }
      panelItems[i] = new Object[] { link, address };
    }
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-warning",
        rb.getString("summary.negativesamenetwork.title"), panelItems,
        rb.getString("summary.negativesamenetwork.body"),
        relayIp, timestampStr, relayIp.contains(":") ? 48 : 24);
  }

  private void writeSummaryPositive(PrintWriter out, ResourceBundle rb,
      String relayIp, String timestampStr) throws IOException {
    String formattedRelayIp = relayIp.contains(":")
        ? "[" + relayIp + "]" : relayIp;
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-success", rb.getString("summary.positive.title"), null,
        rb.getString("summary.positive.body"), formattedRelayIp,
        timestampStr);
  }

  private void writeSummaryNegative(PrintWriter out, ResourceBundle rb,
      String relayIp, String timestampStr) throws IOException {
    String formattedRelayIp = relayIp.contains(":")
        ? "[" + relayIp + "]" : relayIp;
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-warning", rb.getString("summary.negative.title"), null,
        rb.getString("summary.negative.body"), formattedRelayIp,
        timestampStr);
  }

  private void writeSummary(PrintWriter out, String heading,
      String panelContext, String panelTitle, Object[][] panelItems,
      String panelBodyTemplate, Object... panelBodyArgs)
      throws IOException {
    out.printf("      <div class=\"row\">\n"
        + "        <div class=\"col-xs-12\">\n"
        + "          <h2>%s</h2>\n"
        + "          <div class=\"panel %s\">\n"
        + "            <div class=\"panel-heading\">\n"
        + "              <h3 class=\"panel-title\">%s</h3>\n"
        + "            </div><!-- panel-heading -->\n"
        + "            <div class=\"panel-body\">\n"
        + "              <p>%s</p>\n", heading, panelContext, panelTitle,
        String.format(panelBodyTemplate, panelBodyArgs));
    if (panelItems != null) {
      out.print("              <ul>\n");
      for (Object[] panelItem : panelItems) {
        out.printf("                <li><a href=\"%s\">%s</a></li>\n",
            panelItem);
      }
      out.print("              </ul>\n");
    }
    out.print("            </div><!-- panel-body -->\n"
        + "          </div><!-- panel -->\n"
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n");
  }

  private void writeTechnicalDetails(PrintWriter out, ResourceBundle rb,
      String relayIp, String timestampStr, List<String[]> tableRows)
      throws IOException {
    String formattedRelayIp = relayIp.contains(":")
        ? "[" + relayIp + "]" : relayIp;
    out.printf("      <div class=\"row\">\n"
        + "        <div class=\"col-xs-12\">\n"
        + "          <h2>%s</h2>\n"
        + "          <p>%s</p>\n"
        + "          <table class=\"table\">\n"
        + "            <thead>\n"
        + "              <tr>\n"
        + "                <th>%s</th>\n"
        + "                <th>%s</th>\n"
        + "                <th>%s</th>\n"
        + "                <th>%s</th>\n"
        + "                <th>%s</th>\n"
        + "              </tr>\n"
        + "            </thead>\n"
        + "            <tbody>\n",
        rb.getString("technicaldetails.heading"),
        String.format(rb.getString("technicaldetails.pre"),
            formattedRelayIp, timestampStr),
        rb.getString("technicaldetails.colheader.timestamp"),
        rb.getString("technicaldetails.colheader.ip"),
        rb.getString("technicaldetails.colheader.fingerprint"),
        rb.getString("technicaldetails.colheader.nickname"),
        rb.getString("technicaldetails.colheader.exit"));
    for (String[] tableRow : tableRows) {
      out.print("              <tr>");
      for (int i = 0; i < tableRow.length; i++) {
        String attributes = "";
        String content = tableRow[i];
        if (i == 2) {
          attributes = " class=\"fingerprint\"";
        } else if (i == 3 && content == null) {
          content = "("
              + rb.getString("technicaldetails.nickname.unknown") + ")";
        } else if (i == 4) {
          if (content.equals("U")) {
            content = rb.getString("technicaldetails.exit.unknown");
          } else if (content.equals("Y")) {
            content = rb.getString("technicaldetails.exit.yes");
          } else {
            content = rb.getString("technicaldetails.exit.no");
          }
        }
        out.print("                <td" + attributes + ">" + content + "</td>");
      }
      out.print("              </tr>\n");
    }
    out.print("            </tbody>\n"
        + "          </table>\n"
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n");
  }

  private void writePermanentLink(PrintWriter out, ResourceBundle rb,
      String relayIp, String timestampStr, String langStr) throws IOException {
    String encodedAddress = relayIp.contains(":")
        ? "[" + relayIp.replaceAll(":", "%3A") + "]" : relayIp;
    out.printf("      <div class=\"row\">\n"
        + "        <div class=\"col-xs-12\">\n"
        + "          <h2>%s</h2>\n"
        + "          <pre>https://exonerator.torproject.org/?ip=%s&amp;"
          + "timestamp=%s&amp;lang=%s</pre>\n"
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n",
        rb.getString("permanentlink.heading"),
        encodedAddress, timestampStr, langStr);
  }

  private void writeFooter(PrintWriter out, ResourceBundle rb, String relayIp,
      String timestampStr) throws IOException {
    out.printf("    </div><!-- container -->\n"
        + "    <div class=\"footer\">\n"
        + "      <div class=\"container\">\n"
        + "        <div class=\"row\">\n"
        + "          <div class=\"col-xs-6\">\n"
        + "            <h3>%s</h3>\n"
        + "            <p class=\"small\">%s</p>\n"
        + "          </div><!-- col -->\n",
        rb.getString("footer.abouttor.heading"),
        String.format(rb.getString("footer.abouttor.body.text"),
            "<a href=\"https://www.torproject.org/about/"
            + "overview#thesolution\">"
            + rb.getString("footer.abouttor.body.link1") + "</a>",
            "<a href=\"https://www.torproject.org/about/overview\">"
            + rb.getString("footer.abouttor.body.link2") + "</a>",
            "<a href=\"https://www.torproject.org/about/contact\">"
            + rb.getString("footer.abouttor.body.link3") + "</a>"));
    out.printf("          <div class=\"col-xs-6\">\n"
        + "            <h3>%s</h3>\n"
        + "            <p class=\"small\">%s</p>\n"
        + "          </div><!-- col -->\n"
        + "        </div><!-- row -->\n",
        rb.getString("footer.aboutexonerator.heading"),
        rb.getString("footer.aboutexonerator.body"));
    out.printf("        <div class=\"row\">\n"
        + "          <div class=\"col-xs-12\">\n"
        + "            <p class=\"text-center small\">%s",
        rb.getString("footer.language.text"));
    for (Map.Entry<String, String> entry
        : this.availableLanguageNames.entrySet()) {
      if (null != relayIp && null != timestampStr) {
        out.printf(" <a href=\"/?ip=%s&timestamp=%s&lang=%s\">%s</a>",
            relayIp, timestampStr, entry.getKey(), entry.getValue());
      } else {
        out.printf(" <a href=\"/?lang=%s\">%s</a>",
            entry.getKey(), entry.getValue());
      }
    }
    out.printf("</p>\n"
        + "          </div><!-- col -->\n"
        + "        </div><!-- row -->\n"
        + "        <div class=\"row\">\n"
        + "          <div class=\"col-xs-12\">\n"
        + "            <p class=\"text-center small\">%s</p>\n"
        + "          </div><!-- col -->\n"
        + "        </div><!-- row -->\n"
        + "      </div><!-- container -->\n"
        + "    </div><!-- footer -->\n"
        + "  </body>\n"
        + "</html>\n",
        String.format(rb.getString("footer.trademark.text"),
            "<a href=\"https://www.torproject.org/docs/"
            + "trademark-faq.html.en\">"
            + rb.getString("footer.trademark.link") + "</a>"));
    out.close();
  }
}

