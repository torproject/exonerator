/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.exonerator;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;

/** Query response from the ExoneraTor database. */
public class QueryResponse {

  private static Logger logger = LoggerFactory.getLogger(QueryResponse.class);

  /* Actual version implemented by this class. */
  private static final String VERSION = "1.0";

  /* Don't accept query responses with versions lower than this. */
  private static final String FIRSTRECOGNIZEDVERSION = "1.0";

  /* Don't accept query responses with this version or higher. */
  private static final String FIRSTUNRECOGNIZEDVERSION = "2.0";

  private static ObjectMapper objectMapper = new ObjectMapper()
      .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE)
      .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
      .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE)
      .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

  /** Version of this response format. */
  String version = VERSION;

  /**
   * Query IP address passed in the request; never {@code null}.
   */
  String queryAddress;

  /**
   * Query date passed in the request; never {@code null}.
   */
  String queryDate;

  /** ISO-formatted valid-after time of the first status contained in the
   * database; only {@code null} if the database is empty. */
  String firstDateInDatabase;

  /** ISO-formatted valid-after time of the last status contained in the
   * database; only {@code null} if the database is empty. */
  String lastDateInDatabase;

  /** Whether there is at least one relevant status in the database on or within
   * a day of the requested date; {@code null} if the database is empty. */
  Boolean relevantStatuses;

  /** All matches for the given IP address and date; {@code null} if there
   * were no matches at all. */
  Match[] matches;

  /** Constructor for Gson. */
  public QueryResponse() {}

  /** Constructor for tests. */
  QueryResponse(String version, String queryAddress, String queryDate,
      String firstDateInDatabase, String lastDateInDatabase,
      Boolean relevantStatuses, Match[] matches, String[] nearbyAddresses) {
    this.version = version;
    this.queryAddress = queryAddress;
    this.queryDate = queryDate;
    this.firstDateInDatabase = firstDateInDatabase;
    this.lastDateInDatabase = lastDateInDatabase;
    this.relevantStatuses = relevantStatuses;
    this.matches = matches;
    this.nearbyAddresses = nearbyAddresses;
  }

  /** Return JSON string for given QueryResponse. */
  public static String toJson(QueryResponse response) throws IOException {
    return objectMapper.writeValueAsString(response);
  }

  /** Return QueryResponse parsed from the given input stream, or
   * {@code null} if something fails or an unrecognized version is found. */
  public static QueryResponse fromJson(Reader reader) {
    try {
      QueryResponse response = objectMapper.readValue(reader,
          QueryResponse.class);
      if (null == response || null == response.version) {
        logger.warn("Response is either empty or does not contain "
            + "version information.");
        return null;
      } else if (response.version.compareTo(FIRSTRECOGNIZEDVERSION) < 0
          || response.version.compareTo(FIRSTUNRECOGNIZEDVERSION) >= 0) {
        logger.error("Response has version {}, which is not in the range "
            + "of versions we can handle: {} <= x < {}).", response.version,
            FIRSTRECOGNIZEDVERSION, FIRSTUNRECOGNIZEDVERSION);
        return null;
      }
      return response;
    } catch (IOException | RuntimeException e) {
      /* We're catching RuntimeException here, rather than IOException, so that
       * we return null if anything goes wrong, including cases that we did not
       * anticipate. */
      logger.error("JSON decoding failed.", e);
    }
    return null;
  }

  /** Match details. */
  static class Match {

    /** ISO-formatted valid-after time of the status containing the match. */
    String timestamp;

    /** All known IP addresses of the relay at the time. */
    String[] addresses;

    /** Relay fingerprint. */
    String fingerprint;

    /** Relay nickname. */
    String nickname;

    /** Whether this relay permitted exiting or not; {@code null} if
     * unknown. */
    Boolean exit;

    /** Constructor for Gson. */
    public Match() {}

    /** Constructor for tests. */
    Match(String timestamp, String[] addresses, String fingerprint,
        String nickname, Boolean exit) {
      this.timestamp = timestamp;
      this.addresses = addresses;
      this.fingerprint = fingerprint;
      this.nickname = nickname;
      this.exit = exit;
    }
  }

  /** All known IP addresses in the same /24 or /48 network; {@code null}
   * if there were direct matches for the given IP address. */
  String[] nearbyAddresses;
}

