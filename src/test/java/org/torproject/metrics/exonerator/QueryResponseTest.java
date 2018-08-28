/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Collection;
import java.util.TreeSet;

@RunWith(Parameterized.class)
public class QueryResponseTest {

  /** Test data structure: QueryResponse, JSON string. */
  @Parameters
  public static Collection<Object[]> testData() {
    return Arrays.asList(new Object[][] {
        {null,
        "{\"version\":\"0.3\","
          + "\"query_address\":\"12.13.14.15\","
          + "\"query_date\":\"2016-12-12\","
          + "\"first_date_in_database\":\"2016-01-01\","
          + "\"last_date_in_database\":\"2016-12-31\","
          + "\"relevant_statuses\":true,"
          + "\"matches\":[{\"timestamp\":\"2016-12-03\","
          + "\"addresses\":[\"12.13.14.15\","
          + "\"12.13.14.16\"],\"fingerprint\":\"fingerprint-not-checked\","
          + "\"nickname\":\"some name\","
          + "\"exit\":true},{\"timestamp\":\"2012-12-03\","
          + "\"addresses\":[\"12.13.20.15\","
          + "\"12.13.20.16\"],\"fingerprint\":\"fingerprint2-not-checked\","
          + "\"nickname\":\"some name2\","
          + "\"exit\":false}],\"nearby_addresses\":[\"12.13.14.15\","
          + "\"12.13.14.16\"]}"},
        {new QueryResponse("1.1", null, null, null,
          null, false, null, null),
          "{\"version\":\"1.1\",\"relevant_statuses\":false}"},
        {new QueryResponse("1.0", "12.13.14.15", "2016-12-12", "2016-01-01",
          "2016-12-31", true,
        new QueryResponse.Match[]{new QueryResponse.Match("2016-12-03",
        new TreeSet<>(Arrays.asList("12.13.14.15", "12.13.14.16")),
        "fingerprint-not-checked", "some name", true),
          new QueryResponse.Match("2012-12-03",
          new TreeSet<>(Arrays.asList("12.13.20.15", "12.13.20.16")),
          "fingerprint2-not-checked", "some name2", false)},
          new String[] {"12.13.14.15", "12.13.14.16"}),
          "{\"version\":\"1.0\","
          + "\"query_address\":\"12.13.14.15\","
          + "\"query_date\":\"2016-12-12\","
          + "\"first_date_in_database\":\"2016-01-01\","
          + "\"last_date_in_database\":\"2016-12-31\","
          + "\"relevant_statuses\":true,"
          + "\"matches\":[{\"timestamp\":\"2016-12-03\","
          + "\"addresses\":[\"12.13.14.15\","
          + "\"12.13.14.16\"],\"fingerprint\":\"fingerprint-not-checked\","
          + "\"nickname\":\"some name\","
          + "\"exit\":true},{\"timestamp\":\"2012-12-03\","
          + "\"addresses\":[\"12.13.20.15\","
          + "\"12.13.20.16\"],\"fingerprint\":\"fingerprint2-not-checked\","
          + "\"nickname\":\"some name2\","
          + "\"exit\":false}],\"nearby_addresses\":[\"12.13.14.15\","
          + "\"12.13.14.16\"]}"},
        {new QueryResponse("1.0", "12.13.14.15", "2016-12-12", "2016-01-01",
            "2016-12-31", false,
            new QueryResponse.Match[]{new QueryResponse.Match("2016-12-03",
            new TreeSet<>(Arrays.asList("12.13.14.15", "12.13.14.16")),
            "fingerprint-not-checked", "some name", null),
              new QueryResponse.Match("2012-12-03",
              new TreeSet<>(Arrays.asList("12.13.20.15", "12.13.20.16")),
              "fingerprint2-not-checked", "some name2", true)},
            new String[] {"12.13.14.15", "12.13.14.16"}),
          "{\"version\":\"1.0\","
          + "\"query_address\":\"12.13.14.15\","
          + "\"query_date\":\"2016-12-12\","
          + "\"first_date_in_database\":\"2016-01-01\","
          + "\"last_date_in_database\":\"2016-12-31\","
          + "\"relevant_statuses\":false,"
          + "\"matches\":[{\"timestamp\":\"2016-12-03\","
          + "\"addresses\":[\"12.13.14.15\","
          + "\"12.13.14.16\"],\"fingerprint\":\"fingerprint-not-checked\","
          + "\"nickname\":\"some name\"},{\"timestamp\":\"2012-12-03\","
          + "\"addresses\":[\"12.13.20.15\","
          + "\"12.13.20.16\"],\"fingerprint\":\"fingerprint2-not-checked\","
          + "\"nickname\":\"some name2\","
          + "\"exit\":true}],\"nearby_addresses\":[\"12.13.14.15\","
          + "\"12.13.14.16\"]}"}
    });
  }

  private QueryResponse queryResponse;
  private String json;

  public QueryResponseTest(QueryResponse qr, String json) {
    this.queryResponse = qr;
    this.json = json;
  }

  @Test
  public void testJsonReading() throws IOException {
    if (null == this.queryResponse) {
      assertNull(QueryResponse.fromJson(new StringReader(this.json)));
    } else {
      assertEquals(json, QueryResponse
          .toJson(QueryResponse.fromJson(new StringReader(this.json))));
    }
  }

  @Test
  public void testJsonWriting() throws IOException {
    if (null == this.queryResponse) {
      return;
    }
    assertEquals(json, QueryResponse.toJson(this.queryResponse));
  }

}

