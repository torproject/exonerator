/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Locale;
import java.util.ResourceBundle;

public class ExoneraTorServletTest {

  private static final String[][] ipTestData
      = {   // input, output
        {"86.95.81.23", "86.95.81.23"},
        {"786.95.81.23", null},
        {"86.95.81.2334", null},
        {null, ""},
        {"", ""},
        {"[2a01:4f8:190:514a::2]", "2a01:4f8:190:514a::2"},
        {"2a01:4f8:1234:0:5678:0:9abc:d", "2a01:4f8:1234:0:5678:0:9abc:d"},
        {"2a01:4f8:1234:0:5678:0:9abc:u", null},
        {"2a01:4f8::0:9abc:d", "2a01:4f8::0:9abc:d"},
        {"2A01:4F8::0:9ABC:D", "2a01:4f8::0:9abc:d"},
        {"2a01:4f8:::0:9abc:d", null},
        {"[[2a01:4f8:190:514a::2]]", null},
        {"2a01:4f8:190:514a::2", "2a01:4f8:190:514a::2"}
      };

  @Test
  public void testIpParsing() {
    for (String[] data : ipTestData) {
      assertEquals(data[1], ExoneraTorServlet.parseIpParameter(data[0]));
    }
  }

  @Test
  public void testNearbyIpV6Response() throws Exception {
    ExoneraTorServlet es = new ExoneraTorServlet();
    ResourceBundle rb = ResourceBundle
        .getBundle("ExoneraTor", Locale.forLanguageTag("en"));
    for (QueryResponse qr : qrs) {
      StringWriter sw = new StringWriter();
      es.writeSummaryAddressesInSameNetwork(new PrintWriter(sw), rb,
          "http://localhost:8080/", qr.queryAddress, qr.queryDate, "en",
          Arrays.asList(qr.nearbyAddresses));
      String errorMsg = "Test data:" + QueryResponse.toJson(qr)
          + "\nresult:\n" + sw.toString();
      assertTrue(errorMsg,
          sw.toString().contains("Result is negative"));
      assertTrue(errorMsg,
          sw.toString().contains("ip=[2a06%3Ae80%3A1%3A%3A10]&"));
      assertTrue(errorMsg,
          sw.toString().contains("ip=[2a06%3Ae80%3A1%3A%3A15]&"));
    }
  }

  private QueryResponse[] qrs = new QueryResponse[]{
      QueryResponse.fromJson(new StringReader(
          "{\"version\":\"1.0\","
          + "\"query_address\":\"2a06:e80:1::11\","
          + "\"query_date\":\"2016-12-12\","
          + "\"first_date_in_database\":\"2016-01-01\","
          + "\"last_date_in_database\":\"2016-12-31\","
          + "\"relevant_statuses\":false,"
          + "\"nearby_addresses\":[\"2a06:e80:1::10\","
          + "\"2a06:e80:1::15\"]}")),
      QueryResponse.fromJson(new StringReader(
          "{\"version\":\"1.0\","
          + "\"query_address\":\"2a06:e80:1::11\","
          + "\"query_date\":\"2016-12-12\","
          + "\"first_date_in_database\":\"2016-01-01\","
          + "\"last_date_in_database\":\"2016-12-31\","
          + "\"relevant_statuses\":false,"
          + "\"nearby_addresses\":[\"[2a06:e80:1::10]\","
          + "\"2a06:e80:1::15\"]}")),
      QueryResponse.fromJson(new StringReader(
          "{\"version\":\"1.0\","
          + "\"query_address\":\"2a06:e80:1::11\","
          + "\"query_date\":\"2016-12-12\","
          + "\"first_date_in_database\":\"2016-01-01\","
          + "\"last_date_in_database\":\"2016-12-31\","
          + "\"relevant_statuses\":false,"
          + "\"nearby_addresses\":[\"[2a06:e80:1::10]\","
          + "\"[2a06:e80:1::15]\"]}"))};
}

