/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.exonerator;

import com.google.gson.Gson;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Reader;

/** Query response from the ExoneraTor database. */
public class QueryResponse {

  @Expose(serialize = false, deserialize = false)
  private static Logger logger = LoggerFactory.getLogger(QueryResponse.class);

  /* Actual version implemented by this class. */
  @Expose(serialize = false, deserialize = false)
  private static final String VERSION = "1.0";

  /* Don't accept query responses with versions lower than this. */
  @Expose(serialize = false, deserialize = false)
  private static final String FIRSTRECOGNIZEDVERSION = "1.0";

  /* Don't accept query responses with this version or higher. */
  @Expose(serialize = false, deserialize = false)
  private static final String FIRSTUNRECOGNIZEDVERSION = "2.0";

  /** Version of this response format. */
  @Expose
  String version = VERSION;

  /** Query IP address passed in the request; never <code>null</code>. */
  @Expose
  @SerializedName("query_address")
  String queryAddress;

  /** Query date passed in the request; never <code>null</code>. */
  @Expose
  @SerializedName("query_date")
  String queryDate;

  /** ISO-formatted valid-after time of the first status contained in the
   * database; only <code>null</code> if the database is empty. */
  @Expose
  @SerializedName("first_date_in_database")
  String firstDateInDatabase;

  /** ISO-formatted valid-after time of the last status contained in the
   * database; only <code>null</code> if the database is empty. */
  @Expose
  @SerializedName("last_date_in_database")
  String lastDateInDatabase;

  /** Whether there is at least one relevant status in the database on or within
   * a day of the requested date; <code>null</code> if the database is empty. */
  @Expose
  @SerializedName("relevant_statuses")
  Boolean relevantStatuses;

  /** All matches for the given IP address and date; <code>null</code> if there
   * were no matches at all. */
  @Expose
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
  public static String toJson(QueryResponse response) {
    return new Gson().toJson(response);
  }

  /** Return QueryResponse parsed from the given input stream, or
   * {@code null} if something fails or an unrecognized version is found. */
  public static QueryResponse fromJson(Reader reader) {
    Gson gson = new Gson();
    try {
      QueryResponse response = gson.fromJson(reader, QueryResponse.class);
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
    } catch (RuntimeException e) {
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

    /** Whether this relay permitted exiting or not; <code>null</code> if
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

  /** All known IP addresses in the same /24 or /48 network; <code>null</code>
   * if there were direct matches for the given IP address. */
  @Expose
  @SerializedName("nearby_addresses")
  String[] nearbyAddresses;
}

