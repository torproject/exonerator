/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

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
}

