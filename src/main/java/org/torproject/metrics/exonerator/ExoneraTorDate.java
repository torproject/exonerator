/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import static java.time.format.DateTimeFormatter.ISO_LOCAL_DATE;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;

class ExoneraTorDate {

  public static final ExoneraTorDate INVALID = new ExoneraTorDate("");
  private static final int DATELENGTH = "yyyy-mm-dd".length();

  final boolean empty;
  final boolean valid;
  final String asString;
  final LocalDate date;
  final String asRequested;
  final boolean tooRecent;

  ExoneraTorDate(String parameter) {
    this.asRequested = parameter;
    this.empty = null == parameter || parameter.trim().isEmpty();
    this.date = empty ? null : parseDatestamp(parameter);
    this.valid = null != date;
    this.asString = valid ? date.format(ISO_LOCAL_DATE) : "";
    this.tooRecent = valid
        && date.isAfter(LocalDate.now(ZoneOffset.UTC).minusDays(2));
  }

  private static LocalDate parseDatestamp(String datestamp) {
    String trimmedDatestamp = datestamp.replaceAll("\\s", "");
    if (trimmedDatestamp.length() >= DATELENGTH) {
      try {
        return LocalDate
            .parse(trimmedDatestamp.substring(0, DATELENGTH), ISO_LOCAL_DATE);
      } catch (DateTimeParseException e) {
        return null;
      }
    }
    return null;
  }

}
