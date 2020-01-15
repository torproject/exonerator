/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import static java.time.format.DateTimeFormatter.ISO_LOCAL_DATE;
import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class ExoneraTorDateTest {

  /** All test data. */
  @Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][] {   // input, output
        {"2000-   10-10", LocalDate.parse("2000-10-10", ISO_LOCAL_DATE),
         false, true},
        {"2010-12-16 +0001", LocalDate.parse("2010-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2010-12-16 CEST", LocalDate.parse("2010-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2010-12-16abcd", LocalDate.parse("2010-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2010-12-16", LocalDate.parse("2010-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2000-10-10 12:10:00", LocalDate.parse("2000-10-10", ISO_LOCAL_DATE),
         false, true},
        {"2000-10-10 1210-04-05",
         LocalDate.parse("2000-10-10", ISO_LOCAL_DATE), false, true},
        {"20.10.16", null, false, false},
        {null, null, true, false},
        {"", null, true, false},
        {"2010-12 16", null, false, false},
        {"2010-\t12-\t16", LocalDate.parse("2010-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2010- 12- \t16", LocalDate.parse("2010-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2003-12-\t16", LocalDate.parse("2003-12-16", ISO_LOCAL_DATE),
         false, true},
        {"2004-10-14\t", LocalDate.parse("2004-10-14", ISO_LOCAL_DATE),
         false, true},
        {"\n2005-10-12\t\t", LocalDate.parse("2005-10-12", ISO_LOCAL_DATE),
         false, true},
        {"    2001-10-13   ", LocalDate.parse("2001-10-13", ISO_LOCAL_DATE),
         false, true}
    });
  }

  @Parameter(0)
  public String dateParameter;

  @Parameter(1)
  public LocalDate expectedDate;

  @Parameter(2)
  public boolean empty;

  @Parameter(3)
  public boolean valid;

  @Test
  public void testTimestampParsing() {
    ExoneraTorDate date = new ExoneraTorDate(dateParameter);
    assertEquals("Input data: " + dateParameter, expectedDate, date.date);
    assertEquals("Input data: " + dateParameter, empty, date.empty);
    assertEquals("Input data: " + dateParameter, valid, date.valid);
  }

}

