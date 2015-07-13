/* Copyright 2011, 2012 The Tor Project
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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

  public void doGet(HttpServletRequest request,
      HttpServletResponse response) throws IOException,
      ServletException {

    /* Start writing response. */
    PrintWriter out = response.getWriter();
    writeHeader(out);

    /* Open a database connection that we'll use to handle the whole
     * request. */
    Connection conn = null;
    long requestedConnection = System.currentTimeMillis();
    try {
      conn = this.ds.getConnection();
    } catch (SQLException e) {
      out.println("<p><font color=\"red\"><b>Warning: </b></font>Unable "
          + "to connect to the database. If this problem persists, "
          + "please <a href=\"mailto:tor-assistants@torproject.org\">let "
          + "us know</a>!</p>\n");
      writeFooter(out);
      return;
    }

    /* Look up first and last consensus in the database. */
    long firstValidAfter = -1L, lastValidAfter = -1L;
    try {
      Statement statement = conn.createStatement();
      String query = "SELECT MIN(validafter) AS first, "
          + "MAX(validafter) AS last FROM consensus";
      ResultSet rs = statement.executeQuery(query);
      if (rs.next()) {
        firstValidAfter = rs.getTimestamp(1).getTime();
        lastValidAfter = rs.getTimestamp(2).getTime();
      }
      rs.close();
      statement.close();
    } catch (SQLException e) {
      /* Looks like we don't have any consensuses. */
    }
    if (firstValidAfter < 0L || lastValidAfter < 0L) {
      out.println("<p><font color=\"red\"><b>Warning: </b></font>This "
          + "server doesn't have any relay lists available. If this "
          + "problem persists, please "
          + "<a href=\"mailto:tor-assistants@lists.torproject.org\">let "
          + "us know</a>!</p>\n");
      writeFooter(out);
      try {
        conn.close();
        this.logger.info("Returned a database connection to the pool "
            + "after " + (System.currentTimeMillis()
            - requestedConnection) + " millis.");
      } catch (SQLException e) {
      }
      return;
    }

    out.println("<a name=\"relay\"></a><h3>Was there a Tor relay running "
        + "on this IP address?</h3>");

    /* Parse IP parameter. */
    Pattern ipv4AddressPattern = Pattern.compile(
        "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
    Pattern ipv6AddressPattern = Pattern.compile(
        "^\\[?[0-9a-fA-F:]{3,39}\\]?$");
    String ipParameter = request.getParameter("ip");
    String relayIP = "", ipWarning = "";
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
          ipWarning = "\"" + (ipParameter.length() > 40 ?
              StringEscapeUtils.escapeHtml(ipParameter.substring(0, 40))
              + "[...]" : StringEscapeUtils.escapeHtml(ipParameter))
              + "\" is not a valid IP address.";
        }
      } else {
        ipWarning = "\"" + (ipParameter.length() > 20 ?
            StringEscapeUtils.escapeHtml(ipParameter.substring(0, 20))
            + "[...]" : StringEscapeUtils.escapeHtml(ipParameter))
            + "\" is not a valid IP address.";
      }
    }

    /* Parse timestamp parameter. */
    String timestampParameter = request.getParameter("timestamp");
    long timestamp = 0L;
    String timestampStr = "", timestampWarning = "";
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    if (timestampParameter != null && timestampParameter.length() > 0) {
      try {
        timestamp = dateFormat.parse(timestampParameter).getTime();
        timestampStr = dateFormat.format(timestamp);
        if (timestamp < firstValidAfter || timestamp > lastValidAfter) {
          timestampWarning = "Please pick a date between \""
              + dateFormat.format(firstValidAfter) + "\" and \""
              + dateFormat.format(lastValidAfter) + "\".";
          timestamp = 0L;
        }
      } catch (ParseException e) {
        /* We have no way to handle this exception, other than leaving
           timestampStr at "". */
        timestampWarning = "\"" + (timestampParameter.length() > 20 ?
            StringEscapeUtils.escapeHtml(timestampParameter.
            substring(0, 20)) + "[...]" :
            StringEscapeUtils.escapeHtml(timestampParameter))
            + "\" is not a valid date.";
      }
    }

    /* If either IP address or timestamp is provided, the other one must
     * be provided, too. */
    if (relayIP.length() < 1 && timestampStr.length() > 0 &&
        ipWarning.length() < 1) {
      ipWarning = "Please provide an IP address.";
    }
    if (relayIP.length() > 0 && timestamp < 1 &&
        timestampWarning.length() < 1) {
      timestampWarning = "Please provide a date.";
    }

    /* Write form with IP address and timestamp. */
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

    if (relayIP.length() < 1 || timestamp < 1) {
      writeFooter(out);
      try {
        conn.close();
        this.logger.info("Returned a database connection to the pool "
            + "after " + (System.currentTimeMillis()
            - requestedConnection) + " millis.");
      } catch (SQLException e) {
      }
      return;
    }

    out.printf("<p>Looking up IP address %s in the relay lists "
        + "published ", relayIP);
    long timestampFrom, timestampTo;
    /* Consider all consensuses published on or within a day of the given
     * date. */
    timestampFrom = timestamp - 24L * 60L * 60L * 1000L;
    timestampTo = timestamp + 2 * 24L * 60L * 60L * 1000L - 1L;
    out.printf("on or within a day of %s", timestampStr);
    out.print(" as well as in the relevant exit lists. Clients could "
        + "have selected any of these relays to build circuits. "
        + "You may follow the links to relay lists and relay descriptors "
        + "to grep for the lines printed below and confirm that results "
        + "are correct.<br>");
    SimpleDateFormat validAfterTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    validAfterTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String fromValidAfter = validAfterTimeFormat.format(timestampFrom);
    String toValidAfter = validAfterTimeFormat.format(timestampTo);
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
    }
    if (relevantConsensuses.isEmpty()) {
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
      writeFooter(out);
      try {
        conn.close();
        this.logger.info("Returned a database connection to the pool "
            + "after " + (System.currentTimeMillis()
            - requestedConnection) + " millis.");
      } catch (SQLException e) {
      }
      return;
    }

    /* Search for status entries with the given IP address as onion
     * routing address, plus status entries of relays having an exit list
     * entry with the given IP address as exit address. */
    SortedMap<Long, SortedMap<String, String>> statusEntries =
        new TreeMap<Long, SortedMap<String, String>>();
    SortedSet<Long> positiveConsensusesNoTarget = new TreeSet<Long>();
    SortedMap<String, Set<Long>> relevantDescriptors =
        new TreeMap<String, Set<Long>>();
    try {
      CallableStatement cs = conn.prepareCall(
          "{call search_statusentries_by_address_date(?, ?)}");
      cs.setString(1, relayIP);
      cs.setDate(2, new java.sql.Date(timestamp));
      ResultSet rs = cs.executeQuery();
      while (rs.next()) {
        byte[] rawstatusentry = rs.getBytes(1);
        String descriptor = rs.getString(2);
        long validafter = rs.getTimestamp(3).getTime();
        positiveConsensusesNoTarget.add(validafter);
        if (!relevantDescriptors.containsKey(descriptor)) {
          relevantDescriptors.put(descriptor, new HashSet<Long>());
        }
        relevantDescriptors.get(descriptor).add(validafter);
        String fingerprint = rs.getString(4);
        String exitaddress = rs.getString(6);
        StringBuilder html = new StringBuilder();
        for (String line : new String(rawstatusentry).split("\n")) {
          if (line.startsWith("r ")) {
            String[] parts = line.split(" ");
            boolean orAddressMatches = parts[6].equals(relayIP);
            html.append("r " + parts[1] + " " + parts[2] + " "
                + "<a href=\"serverdesc?desc-id=" + descriptor + "\" "
                + "target=\"_blank\">" + parts[3] + "</a> " + parts[4]
                + " " + parts[5] + " " + (orAddressMatches ? "<b>" : "")
                + parts[6] + (orAddressMatches ? "</b>" : "") + " "
                + parts[7] + " " + parts[8] + "\n");
          } else if (line.startsWith("a ") &&
              line.toLowerCase().contains(relayIP)) {
            String address = line.substring("a ".length(),
                line.lastIndexOf(":"));
            String port = line.substring(line.lastIndexOf(":"));
            html.append("a <b>" + address + "</b>" + port + "\n");
          }
        }
        if (exitaddress != null && exitaddress.length() > 0) {
          long scanned = rs.getTimestamp(7).getTime();
          html.append("  [ExitAddress <b>" + exitaddress
              + "</b> " + validAfterTimeFormat.format(scanned) + "]\n");
        }
        if (!statusEntries.containsKey(validafter)) {
          statusEntries.put(validafter, new TreeMap<String, String>());
        }
        statusEntries.get(validafter).put(fingerprint, html.toString());
      }
      rs.close();
      cs.close();
    } catch (SQLException e) {
      /* Nothing found. */
    }

    /* Print out what we found. */
    SimpleDateFormat validAfterUrlFormat = new SimpleDateFormat(
        "yyyy-MM-dd-HH-mm-ss");
    validAfterUrlFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    out.print("<pre><code>");
    for (long consensus : relevantConsensuses) {
      String validAfterDatetime = validAfterTimeFormat.format(consensus);
      String validAfterString = validAfterUrlFormat.format(consensus);
      out.print("valid-after <b>"
          + "<a href=\"consensus?valid-after="
          + validAfterString + "\" target=\"_blank\">"
          + validAfterDatetime + "</b></a>\n");
      if (statusEntries.containsKey(consensus)) {
        for (String htmlString :
            statusEntries.get(consensus).values()) {
          out.print(htmlString);
        }
      }
      out.print("\n");
    }
    out.print("</code></pre>");
    if (relevantDescriptors.isEmpty()) {
      out.printf("        <p>None found!</p>\n"
          + "        <p>Result is NEGATIVE with high certainty!</p>\n"
          + "        <p>We did not find IP "
          + "address " + relayIP + " in any of the relay or exit lists "
          + "that were published on or within a day of %s.</p>\n",
          timestampStr);
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
        }
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
          }
        }
      }
      if (!addressesInSameNetwork.isEmpty()) {
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
      writeFooter(out);
      try {
        conn.close();
        this.logger.info("Returned a database connection to the pool "
            + "after " + (System.currentTimeMillis()
            - requestedConnection) + " millis.");
      } catch (SQLException e) {
      }
      return;
    }

    /* Print out result. */
    if (!positiveConsensusesNoTarget.isEmpty()) {
      out.print("        <p>Result is POSITIVE with high certainty!"
            + "</p>\n"
          + "        <p>We found one or more relays on IP address "
          + relayIP + " in a ");
      out.print("relay list published on or within a day of "
          + timestampStr);
      out.print(" that clients were likely to know.</p>\n");
    } else {
      out.println("        <p>Result is NEGATIVE "
          + "with high certainty!</p>\n");
      out.println("        <p>We did not find any relay on IP address "
          + relayIP
          + " in the relay lists on or within a day of " + timestampStr
          + ".</p>\n");
    }

    try {
      conn.close();
      this.logger.info("Returned a database connection to the pool "
          + "after " + (System.currentTimeMillis()
          - requestedConnection) + " millis.");
    } catch (SQLException e) {
    }
    writeFooter(out);
  }
}

