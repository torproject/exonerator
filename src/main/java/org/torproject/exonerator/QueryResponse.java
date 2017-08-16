/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.exonerator;

import com.google.gson.annotations.SerializedName;

/** Query response from the ExoneraTor database. */
public class QueryResponse {

  /** Query IP address passed in the request; never <code>null</code>. */
  @SerializedName("query_address")
  String queryAddress;

  /** Query date passed in the request; never <code>null</code>. */
  @SerializedName("query_date")
  String queryDate;

  /** ISO-formatted valid-after time of the first status contained in the
   * database; only <code>null</code> if the database is empty. */
  @SerializedName("first_date_in_database")
  String firstDateInDatabase;

  /** ISO-formatted valid-after time of the last status contained in the
   * database; only <code>null</code> if the database is empty. */
  @SerializedName("last_date_in_database")
  String lastDateInDatabase;

  /** Whether there is at least one relevant status in the database on or within
   * a day of the requested date; <code>null</code> if the database is empty. */
  @SerializedName("relevant_statuses")
  Boolean relevantStatuses;

  /** All matches for the given IP address and date; <code>null</code> if there
   * were no matches at all. */
  Match[] matches;

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
  }

  /** All known IP addresses in the same /24 or /48 network; <code>null</code>
   * if there were direct matches for the given IP address. */
  @SerializedName("nearby_addresses")
  String[] nearbyAddresses;
}

