# Changes in version 2.1.0 - 2018-05-29

 * Medium changes
   - Replace Gson with Jackson.

 * Minor changes
   - Remove duplicate [] surrounding suggested IPv6 addresses that
     caused broken links.


# Changes in version 2.0.2 - 2017-12-20

 * Major changes
   - Reject queries for the current day or the day before, because the
     database may not yet contain enough data to correctly answer
     those requests.

 * Minor changes
   - Add catch-all clauses to servlets to catch and log any unforeseen
     errors.


# Changes in version 2.0.1 - 2017-11-22

 * Minor changes
   - Rename root package org.torproject.exonerator to
     org.torproject.metrics.exonerator to make it part of the Tor
     Metrics name space.
   - Sort results under technical details by timestamp and, if
     necessary, by fingerprint.


# Changes in version 2.0.0 - 2017-11-14

 * Major changes
   - Use an embedded Jetty.


# Changes in version 1.0.3 - 2017-10-16

 * Major changes
   - Handle parameter issues before database problems.


# Changes in version 1.0.2 - 2017-10-16

 * Major changes
   - Fix NullPointerException caused by invalid parameters.

 * Minor changes
   - Resolve checkstyle warnings from more recent guidelines.
   - Update from Apache Commons Lang 2 to 3.


# Changes in version 1.0.1 - 2017-09-16

 * Medium changes
   - Tweak new query towards using an existing index.


# Changes in version 1.0.0 - 2017-09-15

 * Major changes
   - This is the initial release after over seven years of
     development.

