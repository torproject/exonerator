-- Copyright 2011--2018 The Tor Project
-- See LICENSE for licensing information

--------------------------------------------------------------------------------
-- This schema has been superseded by exonerator2.sql:
--  - Existing databases can be migrated by running exonerator2.sql. See the
--    instructions in that file for details.
--  - New databases need to be initialized by running this script first and then
--    exonerator2.sql.
--  - At some point in the future this file will disappear, and exonerator2.sql
--    will be modified to create a new database from scratch.
--------------------------------------------------------------------------------

-- The statusentry table stores network status consensus entries listing
-- a relay as running at a certain point in time.  Only relays with the
-- Running flag shall be inserted into this table.  If a relay advertises
-- more than one IP address, there is a distinct entry for each address in
-- this table.  If a relay advertises more than one TCP port on the same
-- IP address, there is only a single entry in this table.
CREATE TABLE statusentry (

  -- The valid-after time of the consensus that contains this entry.
  validafter TIMESTAMP WITHOUT TIME ZONE NOT NULL,

  -- The 40-character lower-case hex string uniquely identifying the
  -- relay.
  fingerprint CHARACTER(40) NOT NULL,

  -- The most significant 3 bytes of the relay's onion routing IPv4
  -- address in lower-case hex notation, or null if the relay's onion
  -- routing address in this status entry is IPv6.  The purpose is to
  -- quickly reduce query results for relays in the same /24 network.
  oraddress24 CHARACTER(6),

  -- The most significant 6 bytes of the relay's onion routing IPv6
  -- address in lower-case hex notation, or null if the relay's onion
  -- routing address in this status entry is IPv4.  The purpose is to
  -- quickly reduce query results for relays in the same /48 network.
  oraddress48 CHARACTER(12),

  -- The relay's onion routing address.  Can be an IPv4 or an IPv6
  -- address.  If a relay advertises more than one address, there are
  -- multiple entries in this table for the same status entry.
  oraddress INET NOT NULL,

  -- The raw status entry string as contained in the network status
  -- consensus for display purposes only.
  rawstatusentry BYTEA NOT NULL,

  -- A status entry is uniquely identified by its valid-after time, relay
  -- fingerprint, and onion routing address.
  CONSTRAINT statusentry_pkey
      PRIMARY KEY (validafter, fingerprint, oraddress)
);

-- The index on the valid-after time is used to return first and last
-- date in the database and known valid-after times in a given interval.
CREATE INDEX statusentry_validafter ON statusentry (validafter);

-- The index on the exact onion routing address and on the valid-after
-- date is used to speed up ExoneraTor's query for status entries.
CREATE INDEX statusentry_oraddress_validafterdate
    ON statusentry (oraddress, DATE(validafter));

-- The index on the most significant 3 bytes of the relay's onion routing
-- address and on the valid-after date is used to speed up queries for
-- other relays in the same /24 network.
CREATE INDEX statusentry_oraddress24_validafterdate
    ON statusentry (oraddress24, DATE(validafter));

-- The index on the most significant 6 bytes of the relay's onion routing
-- address and on the valid-after date is used to speed up queries for
-- other relays in the same /48 network.
CREATE INDEX statusentry_oraddress48_validafterdate
    ON statusentry (oraddress48, DATE(validafter));

-- The index on fingerprint and valid-after time speeds up joins with
-- exitlistentry.
CREATE INDEX statusentry_fingerprint_validafter_fingerprint
    ON statusentry (fingerprint, validafter);

-- The exitlistentry table stores the results of the active testing,
-- DNS-based exit list for exit nodes.  An entry in this table means that
-- a relay was scanned at a given time and found to be exiting to the
-- Internet from a given IP address.  This IP address can be different
-- from the relay's onion routing address if the relay uses more than one
-- IP addresses.
CREATE TABLE exitlistentry (

  -- The 40-character lower-case hex string identifying the relay.
  fingerprint CHARACTER(40) NOT NULL,

  -- The most significant 3 bytes of the relay's exit IPv4 address in
  -- lower-case hex notation, or null if the relay's exit address in this
  -- entry is IPv6.  The purpose is to quickly reduce query results for
  -- relays exiting from the same /24 network.
  exitaddress24 CHARACTER(6),

  -- The IP address that the relay uses for exiting to the Internet.  If
  -- the relay uses more than one IP address, there are multiple entries
  -- in this table.
  exitaddress INET NOT NULL,

  -- The time when the relay was scanned to find out its exit IP
  -- address(es).
  scanned TIMESTAMP WITHOUT TIME ZONE NOT NULL,

  -- An exit list entry is uniquely identified by its scan time, relay
  -- fingerprint, and exit address.
  CONSTRAINT exitlistentry_pkey
      PRIMARY KEY (scanned, fingerprint, exitaddress)
);

-- The index on the exact exit address and on the valid-after date is used
-- to speed up ExoneraTor's query for status entries referencing exit list
-- entries.
CREATE INDEX exitlistentry_exitaddress_scanneddate
    ON exitlistentry (exitaddress, DATE(scanned));

-- The index on the most significant 3 bytes of the relay's exit address
-- and on the valid-after date is used to speed up queries for other
-- relays in the same /24 network.
CREATE INDEX exitlistentry_exitaddress24_scanneddate
    ON exitlistentry (exitaddress24, DATE(scanned));

-- Create the plpgsql language, so that we can use it below.
CREATE LANGUAGE plpgsql;

-- Insert a status entry into the statusentry table.  First check that
-- this status entry isn't contained in the table yet.  It's okay to
-- insert the same status entry multiple times for different IP addresses
-- though.  Return 1 if it was inserted, 0 otherwise.  (Removed
-- statusentry.descriptor from table on August 17, 2016.)
CREATE OR REPLACE FUNCTION insert_statusentry (
    insert_validafter TIMESTAMP WITHOUT TIME ZONE,
    insert_fingerprint CHARACTER(40),
    insert_descriptor CHARACTER(40),
    insert_oraddress24 CHARACTER(6),
    insert_oraddress48 CHARACTER(12),
    insert_oraddress TEXT,
    insert_rawstatusentry BYTEA)
    RETURNS INTEGER AS $$
  BEGIN
    -- Look up if the status entry is already contained in the statusentry
    -- table.
    IF (SELECT COUNT(*)
        FROM statusentry
        WHERE validafter = insert_validafter
        AND fingerprint = insert_fingerprint
        AND oraddress = insert_oraddress::INET) = 0 THEN
      -- Insert the status entry.
      INSERT INTO statusentry (validafter, fingerprint,
            oraddress24, oraddress48, oraddress, rawstatusentry)
          VALUES (insert_validafter, insert_fingerprint,
            insert_oraddress24, insert_oraddress48,
            insert_oraddress::INET, insert_rawstatusentry);
      -- Return 1 for a successfully inserted status entry.
      RETURN 1;
    ELSE
      -- Return 0 because we already had this status entry.
      RETURN 0;
    END IF;
  END;
$$ LANGUAGE 'plpgsql';

-- Insert an exit list entry into the exitlistentry table.  Check that
-- this entry hasn't been inserted before.  It's okay to insert the same
-- exit list entry multiple times for different exit addresses.  Return 1
-- if the entry was inserted, 0 otherwise.  (Removed
-- exitlistentry.rawexitlistentry from table on August 17, 2016.)
CREATE OR REPLACE FUNCTION insert_exitlistentry (
    insert_fingerprint CHARACTER(40),
    insert_exitaddress24 CHARACTER(6),
    insert_exitaddress TEXT,
    insert_scanned TIMESTAMP WITHOUT TIME ZONE,
    insert_rawexitlistentry BYTEA)
    RETURNS INTEGER AS $$
  BEGIN
    IF (SELECT COUNT(*)
        FROM exitlistentry
        WHERE fingerprint = insert_fingerprint
        AND exitaddress = insert_exitaddress::INET
        AND scanned = insert_scanned) = 0 THEN
      -- This exit list entry is not in the database yet.  Add it.
      INSERT INTO exitlistentry (fingerprint, exitaddress24, exitaddress,
            scanned)
          VALUES (insert_fingerprint, insert_exitaddress24,
            insert_exitaddress::INET, insert_scanned);
      -- Return 1 for a successfully inserted exit list entry.
      RETURN 1;
    ELSE
      -- Return 0 to show that we didn't add anything.
      RETURN 0;
    END IF;
  END;
$$ LANGUAGE 'plpgsql';

-- Search for status entries with an IPv4 onion routing address in the
-- same /24 network as the given hex-encoded IP address prefix and with a
-- valid-after date within a day of the given date, plus status entries of
-- relays having an exit list entry with an exit address in the same /24
-- network as the given hex-encoded IP address prefix and with a scan time
-- within a day of the given date.
CREATE OR REPLACE FUNCTION search_by_address24_date (
    select_address24 TEXT,
    select_date DATE)
    RETURNS TABLE(rawstatusentry BYTEA,
          validafter TIMESTAMP WITHOUT TIME ZONE,
          fingerprint CHARACTER(40),
          exitaddress TEXT) AS $$
  BEGIN
  RETURN QUERY EXECUTE
  -- The first and second selects retrieve the first and last valid-after
  -- time in the database.
  --
  -- The third select retrieves known valid-after times from 1 day before
  -- to 1 day after the given date.
  --
  -- The fourth select finds all status entries of relays with the given
  -- IP address as onion routing address.
  --
  -- The fifth select finds status entries of relays having an exit list
  -- entry with the provided IP address as the exit address.
  -- In the fifth select,
  --  - Focus on a time period from 1 day before and 1 day after the
  -- given date.  Also include a second day before the given date
  -- for exit lists, because it can take up to 24 hours to scan a
  -- relay again.  We should not miss exit list entries here.
  --  - Consider only exit list scans that took place in the 24 hours
  -- before the relay was listed in a consensus.
  'SELECT NULL::BYTEA, MIN(validafter), NULL::CHARACTER, NULL::TEXT
      FROM statusentry
  UNION
  SELECT NULL::BYTEA, MAX(validafter), NULL::CHARACTER, NULL::TEXT
      FROM statusentry
  UNION
  SELECT DISTINCT NULL::BYTEA, validafter, NULL::CHARACTER, NULL::TEXT
      FROM statusentry
      WHERE validafter BETWEEN (''' || select_date || '''::DATE - 1
          || '' 00:00:00'')::TIMESTAMP WITHOUT TIME ZONE
      AND (''' || select_date || '''::DATE + 1
          || '' 23:59:59'')::TIMESTAMP WITHOUT TIME ZONE
  UNION
  SELECT rawstatusentry,
        validafter,
        fingerprint,
        NULL
      FROM statusentry
      WHERE oraddress24 = ''' || select_address24 || '''
      AND DATE(validafter) >= ''' || select_date || '''::DATE - 1
      AND DATE(validafter) <= ''' || select_date || '''::DATE + 1
  UNION
  SELECT DISTINCT statusentry.rawstatusentry,
        statusentry.validafter,
        statusentry.fingerprint,
        HOST(exitlistentry.exitaddress)
      FROM statusentry
      JOIN exitlistentry
      ON statusentry.fingerprint = exitlistentry.fingerprint
      WHERE exitlistentry.exitaddress24 = ''' || select_address24 || '''
      AND DATE(exitlistentry.scanned) >= ''' || select_date
          || '''::DATE - 2
      AND DATE(exitlistentry.scanned) <= ''' || select_date
          || '''::DATE + 1
      AND DATE(statusentry.validafter) >= ''' || select_date
          || '''::DATE - 1
      AND DATE(statusentry.validafter) <= ''' || select_date
          || '''::DATE + 1
      AND statusentry.validafter >= exitlistentry.scanned
      AND statusentry.validafter - exitlistentry.scanned <=
          ''1 day''::INTERVAL';
  END;
$$ LANGUAGE plpgsql;

-- Search for status entries with an IPv6 onion routing address in the
-- same /48 network as the given hex-encoded IP address prefix and with a
-- valid-after date within a day of the given date.
CREATE OR REPLACE FUNCTION search_by_address48_date (
    select_address48 TEXT,
    select_date DATE)
    RETURNS TABLE(rawstatusentry BYTEA,
          validafter TIMESTAMP WITHOUT TIME ZONE,
          fingerprint CHARACTER(40),
          exitaddress TEXT) AS $$
  BEGIN
  RETURN QUERY EXECUTE
  'SELECT NULL::BYTEA, MIN(validafter), NULL::CHARACTER, NULL::TEXT
      FROM statusentry
  UNION
  SELECT NULL::BYTEA, MAX(validafter), NULL::CHARACTER, NULL::TEXT
      FROM statusentry
  UNION
  SELECT DISTINCT NULL::BYTEA, validafter, NULL::CHARACTER, NULL::TEXT
      FROM statusentry
      WHERE validafter BETWEEN (''' || select_date || '''::DATE - 1
          || '' 00:00:00'')::TIMESTAMP WITHOUT TIME ZONE
      AND (''' || select_date || '''::DATE + 1
          || '' 23:59:59'')::TIMESTAMP WITHOUT TIME ZONE
  UNION
  SELECT rawstatusentry,
        validafter,
        fingerprint,
        NULL::TEXT
      FROM statusentry
      WHERE oraddress48 = ''' || select_address48 || '''
      AND DATE(validafter) >= ''' || select_date || '''::DATE - 1
      AND DATE(validafter) <= ''' || select_date || '''::DATE + 1';
  END;
$$ LANGUAGE plpgsql;

