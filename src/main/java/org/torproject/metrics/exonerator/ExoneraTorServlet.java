/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import org.apache.commons.lang3.StringEscapeUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExoneraTorServlet extends HttpServlet {

  private static final long serialVersionUID = 1370088989739567509L;

  private Logger logger;

  private String exoneraTorHost = System.getProperty("exonerator.url",
      "https://exonerator.torproject.org");

  private List<String> availableLanguages =
      Arrays.asList("de", "en", "fr", "ro", "sv");

  private SortedMap<String, String> availableLanguageNames;

  @Override
  public void init(ServletConfig config) throws ServletException {
    super.init(config);
    this.logger = LoggerFactory.getLogger(ExoneraTorServlet.class);
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

    /* Step 1: Parse the request. */

    /* Parse ip parameter. */
    String ipParameter = request.getParameter("ip");
    String relayIp = parseIpParameter(ipParameter);
    final boolean relayIpHasError = relayIp == null;

    /* Parse timestamp parameter. */
    String timestampParameter = request.getParameter("timestamp");
    String timestampStr = parseTimestampParameter(timestampParameter);
    final boolean timestampHasError = timestampStr == null;

    /* Parse lang parameter. */
    String langParameter = request.getParameter("lang");
    String langStr = "en";
    if (null != langParameter
        && this.availableLanguages.contains(langParameter)) {
      langStr = langParameter;
    }

    /* Step 2: Query the backend server. */

    boolean successfullyConnectedToBackend = false;
    String firstDate = null;
    String lastDate = null;
    boolean noRelevantConsensuses = true;
    List<String[]> statusEntries = new ArrayList<>();
    List<String> addressesInSameNetwork = null;

    /* Only query, if we received valid user input. */
    if (null != relayIp && !relayIp.isEmpty() && null != timestampStr
        && !timestampStr.isEmpty()) {
      QueryResponse queryResponse = this.queryBackend(relayIp, timestampStr);
      if (null != queryResponse) {
        successfullyConnectedToBackend = true;
        firstDate = queryResponse.firstDateInDatabase;
        lastDate = queryResponse.lastDateInDatabase;
        if (null != queryResponse.relevantStatuses
            && queryResponse.relevantStatuses) {
          noRelevantConsensuses = false;
        }
        if (null != queryResponse.matches) {
          for (QueryResponse.Match match : queryResponse.matches) {
            StringBuilder sb = new StringBuilder();
            int writtenAddresses = 0;
            for (String address : match.addresses) {
              sb.append((writtenAddresses++ > 0 ? ", " : "") + address);
            }
            String[] statusEntry = new String[]{match.timestamp,
                sb.toString(), match.fingerprint, match.nickname,
                null == match.exit ? "U" : (match.exit ? "Y" : "N")};
            statusEntries.add(statusEntry);
          }
        }
        if (null != queryResponse.nearbyAddresses) {
          addressesInSameNetwork = Arrays.asList(queryResponse.nearbyAddresses);
        }
      }
    }

    /* Step 3: Write the response. */

    /* Set content type, or the page doesn't render in Chrome. */
    response.setContentType("text/html");
    response.setCharacterEncoding("utf-8");

    /* Find the right resource bundle for the user's requested language. */
    ResourceBundle rb = ResourceBundle.getBundle("ExoneraTor",
        Locale.forLanguageTag(langStr));

    /* Start writing response. */
    StringWriter so = new StringWriter();
    PrintWriter out = new PrintWriter(so);
    this.writeHeader(out, rb, langStr);

    /* Write form. */
    boolean timestampOutOfRange = null != timestampStr
        && (null != firstDate && timestampStr.compareTo(firstDate) < 0
        || (null != lastDate && timestampStr.compareTo(lastDate) > 0));
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

    /* If only one parameter is empty and the other is not, print summary with
     * warning message and exit. */
    } else if ("".equals(relayIp)) {
      this.writeSummaryNoIp(out, rb);
      this.writeFooter(out, rb, null, null);
    } else if ("".equals(timestampStr)) {
      this.writeSummaryNoTimestamp(out, rb);
      this.writeFooter(out, rb, null, null);

    /* If there's an issue with parsing either of the parameters, print summary
     * with error message and exit. */
    } else if (relayIpHasError) {
      this.writeSummaryInvalidIp(out, rb, ipParameter);
      this.writeFooter(out, rb, null, null);
    } else if (timestampHasError) {
      this.writeSummaryInvalidTimestamp(out, rb, timestampParameter);
      this.writeFooter(out, rb, null, null);

    /* If we were unable to connect to the database, write an error message. */
    } else if (!successfullyConnectedToBackend) {
      this.writeSummaryUnableToConnectToBackend(out, rb);
      this.writeFooter(out, rb, null, null);

    /* Similarly, if we found the database to be empty, write an error message,
     * too. */
    } else if (null == firstDate || null == lastDate) {
      this.writeSummaryNoData(out, rb);
      this.writeFooter(out, rb, null, null);

    /* If the requested date is out of range, tell the user. */
    } else if (timestampOutOfRange) {
      this.writeSummaryTimestampOutsideRange(out, rb, timestampStr,
          firstDate, lastDate);
      this.writeFooter(out, rb, relayIp, timestampStr);

    } else if (noRelevantConsensuses) {
      this.writeSummaryNoDataForThisInterval(out, rb);
      this.writeFooter(out, rb, relayIp, timestampStr);

    /* Print out result. */
    } else {
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
      this.writeFooter(out, rb, relayIp, timestampStr);
    }

    /* Forward to the JSP that adds header and footer. */
    request.setAttribute("lang", langStr);
    request.setAttribute("body", so.toString());
    request.getRequestDispatcher("WEB-INF/index.jsp").forward(request,
        response);
  }

  /* Helper methods for handling the request. */

  /** Parse an IP parameter and return either a non-<code>null</code> value in
   * case the parameter was valid or empty, or <code>null</code> if it was
   * non-empty and invalid. */
  static String parseIpParameter(String passedIpParameter) {
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

  /** Parse a timestamp parameter and return either a non-<code>null</code>
   * value in case the parameter was valid or empty, or <code>null</code> if it
   * was non-empty and invalid. */
  static String parseTimestampParameter(String passedTimestampParameter) {
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

  /* Helper method for fetching a query response via URL. */

  private QueryResponse queryBackend(String relayIp, String timestampStr) {
    try (InputStreamReader isr = new InputStreamReader(new URL(
        this.exoneraTorHost + "/query.json?ip=" + relayIp + "&timestamp="
        + timestampStr).openStream())) {
      return QueryResponse.fromJson(isr);
    } catch (IOException e) {
      /* No result from backend, so that we don't have a query response to
       * process further. */
      logger.error("Backend query failed.", e);
    }
    return null;
  }

  /* Helper methods for writing the response. */

  private void writeHeader(PrintWriter out, ResourceBundle rb, String langStr)
      throws IOException {
    out.printf("    <div class=\"container\">\n");
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

  private void writeSummaryUnableToConnectToBackend(PrintWriter out,
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
        ? StringEscapeUtils.escapeHtml4(ipParameter.substring(0, 40))
        + "[...]" : StringEscapeUtils.escapeHtml4(ipParameter);
    this.writeSummary(out, rb.getString("summary.heading"),
        "panel-danger",
        rb.getString("summary.invalidparams.invalidip.title"), null,
        rb.getString("summary.invalidparams.invalidip.body"),
        escapedIpParameter, "\"a.b.c.d\"", "\"[a:b:c:d:e:f:g:h]\"");
  }

  private void writeSummaryInvalidTimestamp(PrintWriter out,
      ResourceBundle rb, String timestampParameter) throws IOException {
    String escapedTimestampParameter = timestampParameter.length() > 20
        ? StringEscapeUtils.escapeHtml4(timestampParameter
        .substring(0, 20)) + "[...]"
        : StringEscapeUtils.escapeHtml4(timestampParameter);
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
          switch (content) {
            case "U":
              content = rb.getString("technicaldetails.exit.unknown");
              break;
            case "Y":
              content = rb.getString("technicaldetails.exit.yes");
              break;
            case "N":
              content = rb.getString("technicaldetails.exit.no");
              break;
            default: // should never happen
              logger.warn("Unknown content: '{}'.", content);
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
        + "    <div class=\"container\">\n"
        + "      <div class=\"row\">\n"
        + "        <div class=\"col-xs-6\">\n"
        + "          <h3>%s</h3>\n"
        + "          <p class=\"small\">%s</p>\n"
        + "        </div><!-- col -->\n",
        rb.getString("footer.abouttor.heading"),
        String.format(rb.getString("footer.abouttor.body.text"),
            "<a href=\"https://www.torproject.org/about/"
            + "overview#thesolution\">"
            + rb.getString("footer.abouttor.body.link1") + "</a>",
            "<a href=\"https://www.torproject.org/about/overview\">"
            + rb.getString("footer.abouttor.body.link2") + "</a>",
            "<a href=\"https://www.torproject.org/about/contact\">"
            + rb.getString("footer.abouttor.body.link3") + "</a>"));
    out.printf("        <div class=\"col-xs-6\">\n"
        + "          <h3>%s</h3>\n"
        + "          <p class=\"small\">%s</p>\n"
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n",
        rb.getString("footer.aboutexonerator.heading"),
        rb.getString("footer.aboutexonerator.body"));
    out.printf("      <div class=\"row\">\n"
        + "        <div class=\"col-xs-12\">\n"
        + "          <p class=\"text-center small\">%s",
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
        + "        </div><!-- col -->\n"
        + "      </div><!-- row -->\n"
        + "    </div><!-- container -->\n");
    out.close();
  }
}

