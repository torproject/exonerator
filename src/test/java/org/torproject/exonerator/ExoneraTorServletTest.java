/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.exonerator;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;

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

  private static final String[][] timestampTestData
      = {   // input, output
        {"2000-   10-10", "2000-10-10"},
        {"2010-12-16 +0001", "2010-12-16"},
        {"2010-12-16 CEST", "2010-12-16"},
        {"2010-12-16abcd", "2010-12-16"},
        {"2010-12-16", "2010-12-16"},
        {"2000-10-10 12:10:00", "2000-10-10"},
        {"2000-10-10 1210-04-05", "2000-10-10"},
        {"20.10.16", null},
        {null, ""},
        {"", ""},
        {"2010-12 16", null},
        {"2010-\t12-\t16", "2010-12-16"},
        {"2010- 12- \t16", "2010-12-16"},
        {"2003-12-\t16", "2003-12-16"},
        {"2004-10-10\t", "2004-10-10"},
        {"\n2005-10-10\t\t", "2005-10-10"},
        {"    2001-10-10   ", "2001-10-10"}
      };

  @Test
  public void testTimestampParsing() {
    for (String[] data : timestampTestData) {
      assertEquals(data[1], ExoneraTorServlet.parseTimestampParameter(data[0]));
    }
  }

}

