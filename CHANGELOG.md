# Changes in version 4.?.? - 2019-1?-??

 * Medium changes
   - Turn absolute links to nearby addresses and translations into
     relative links to avoid falling back to http://. Use the base URL
     from the deployment descriptor for the printed permanent link,
     also to avoid falling back to http://.


# Changes in version 4.2.0 - 2019-11-09

 * Medium changes
   - Use Ivy for resolving external dependencies rather than relying
     on files found in Debian stable packages. Requires installing Ivy
     (using `apt-get install ivy`, `brew install ivy`, or similar) and
     running `ant resolve` (or `ant -lib /usr/share/java resolve`).
     Retrieved files are then copied to the `lib/` directory, except
     for dependencies on other metrics libraries that still need to be
     copied to the `lib/` directory manually. Current dependency
     versions resolved by Ivy are the same as in Debian stretch with
     few exceptions.
   - Remove Cobertura from the build process.
   - Update PostgreSQL JDBC driver version to 42.2.5.
   - Update to metrics-lib 2.9.1.


# Changes in version 4.1.0 - 2019-05-13

 * Medium changes
   - Stop signing jars.
   - Use Java 8 date-time functionality.

 * Minor changes
   - Remove first link under "About Tor" and change second and third
     link to adapt to redesigned Tor website.


# Changes in version 4.0.0 - 2018-08-14

 * Major changes
   - Reduce database size and variance of query response times.


# Changes in version 3.0.1 - 2018-08-28

 * Medium changes
   - Fix links to IP addresses in same /24.

 * Minor changes
   - Make several improvements to the code, none of which should
     affect operation.


# Changes in version 3.0.0 - 2018-08-13

 * Major changes
   - Add a new ExoneraTorRedirectServlet that redirects to Tor
     Metrics, and make it the default.

 * Medium changes
   - Prepare ExoneraTorServlet for integration into Tor Metrics.

 * Minor changes
   - Provide a thin jar file without dependencies.


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

