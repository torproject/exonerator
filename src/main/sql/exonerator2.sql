-- Copyright 2011--2020 The Tor Project
-- See LICENSE for licensing information

--------------------------------------------------------------------------------
-- This schema supersedes exonerator.sql:
--  - Existing databases can be migrated by running this script. It is highly
--    recommended to read this file before migrating.
--  - New databases need to be initialized by running exonerator.sql first and
--    then this script.
--  - At some point in the future exonerator.sql will disappear, and this file
--    will be modified to create a new database from scratch.
--------------------------------------------------------------------------------

-- How to migrate from exonerator.sql:
-- - Migration takes a while! And it can break. Read this script first!
-- - Make sure there is at least 50% disk space left and the machine is
--   connected to power.
-- - Turn off the importer cronjob, make sure it is not currently running, and
--   otherwise wait for it to finish.
-- - Back up the database and possibly move the backup offsite, if otherwise
--   there is less than 50% disk space left to complete the migration.
-- - Run this script, either step by step or as a whole. It's going to take a
--   while.
-- - Update the Java importer and servlets to use the new functions.
-- - Turn the importer back on.

-- Exit on first error, which prevents multiple executions of this file.
\set ON_ERROR_STOP true

-- The fingerprint table stores fingerprint strings uniquely identifying relays
-- and assigns much shorter numeric identifiers for internal-only use.
CREATE TABLE fingerprint (

  -- The auto-incremented numeric identifier for a unique fingerprint.
  fingerprint_id SERIAL PRIMARY KEY,

  -- The 27-character base64-encoded string uniquely identifying the relay.
  fingerprint_base64 CHARACTER(27) UNIQUE NOT NULL
);

-- The nickname table stores nickname strings for display in the results table
-- and assigns much shorter numeric identifiers for internal-only use.
CREATE TABLE nickname (

  -- The auto-incremented numeric identifier for a unique nickname.
  nickname_id SERIAL PRIMARY KEY,

  -- The 1 to 19 character long alphanumeric nickname assigned to the relay by
  -- its operator.
  nickname CHARACTER VARYING(19) UNIQUE NOT NULL
);

-- The date_address24 table is the main lookup table. It contains all
-- fingerprints seen in the network on a given date and with a given /24
-- address prefix.
CREATE TABLE date_address24 (

  -- The auto-incremented numeric identifier for an entry in this table.
  date_address24_id SERIAL PRIMARY KEY,

  -- The date when the relay was listed in a network status consensus or scanned
  -- by the exit scanner and contained in an exit list.
  date DATE NOT NULL,

  -- The most significant 3 bytes of the relay's IPv4 or IPv6 address in
  -- lower-case hex notation. The purpose of this notation is to quickly reduce
  -- query results and to enable searches for relays in the same /24 network.
  -- Can be NULL to store the information that there is data available for a
  -- given date.
  address24 CHARACTER(6),

  -- The numeric fingerprint identifier uniquely identifying the relay. Can be
  -- NULL to store the information that there is data available for a given
  -- date.
  fingerprint_id integer REFERENCES fingerprint (fingerprint_id),

  UNIQUE (date, address24, fingerprint_id)
);

-- The statusentry_oraddress table stores network status consensus entries
-- listing a relay as running at a certain point in time. Only relays with the
-- Running flag shall be inserted into this table. If a relay advertises more
-- than one IP address, there is a distinct entry for each address in this
-- table. If a relay advertises more than one TCP port on the same IP address,
-- there is only a single entry in this table.
CREATE TABLE statusentry_oraddress (

  -- The auto-incremented numeric identifier for an entry in this table.
  statusentry_oraddress_id BIGSERIAL PRIMARY KEY,

  -- The valid-after time of the consensus that contains this entry.
  validafter TIMESTAMP WITHOUT TIME ZONE NOT NULL,

  -- The numeric fingerprint identifier uniquely identifying the relay.
  fingerprint_id integer REFERENCES fingerprint (fingerprint_id) NOT NULL,

  -- The relay's onion routing address. Can be an IPv4 or an IPv6 address. If a
  -- relay advertises more than one address, there are multiple entries in this
  -- table for the same status entry.
  oraddress INET NOT NULL,

  -- The numeric nickname identifier referencing the relay nickname.
  nickname_id integer REFERENCES nickname (nickname_id) NOT NULL,

  -- Whether the relay permitted exiting, which can be TRUE, FALSE, or NULL for
  -- unknown.
  exit BOOLEAN,

  UNIQUE (validafter, fingerprint_id, oraddress)
);

-- The exitlistentry_exitaddress table stores the results of the active testing,
-- DNS-based exit list for exit nodes. An entry in this table means that a relay
-- was scanned at a given time and found to be exiting to the Internet from a
-- given IP address. This IP address can be different from the relay's onion
-- routing address if the relay uses more than one IP addresses.
CREATE TABLE exitlistentry_exitaddress (

  -- The auto-incremented numeric identifier for an entry in this table.
  exitlistentry_exitaddress_id SERIAL PRIMARY KEY,

  -- The numeric fingerprint identifier uniquely identifying the relay.
  fingerprint_id integer REFERENCES fingerprint (fingerprint_id) NOT NULL,

  -- The IP address that the relay uses for exiting to the Internet. If the
  -- relay uses more than one IP address, there are multiple entries in this
  -- table.
  exitaddress INET NOT NULL,

  -- The time when the relay was scanned to find out its exit IP address(es).
  scanned TIMESTAMP WITHOUT TIME ZONE NOT NULL,

  -- An exit list entry is uniquely identified by its scan time, relay
  -- fingerprint ID, and exit address.
  UNIQUE (scanned, fingerprint_id, exitaddress)
);

-- Insert the given base64-encoded fingerprint into the fingerprint table, if
-- it's not yet contained, and return the fingerprint identifier.
CREATE OR REPLACE FUNCTION insert_fingerprint (
    insert_fingerprint_base64 CHARACTER(27))
    RETURNS INTEGER AS $$
DECLARE
  result INTEGER;
BEGIN
  SELECT fingerprint_id
  INTO result
  FROM fingerprint
  WHERE fingerprint_base64 = insert_fingerprint_base64;
  IF result IS NULL THEN
    INSERT INTO fingerprint(fingerprint_id, fingerprint_base64)
    VALUES (DEFAULT, insert_fingerprint_base64)
    RETURNING fingerprint_id INTO result;
  END IF;
  RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Insert the given nickname into the nickname table, if it's not yet contained,
-- and return the nickname identifier.
CREATE OR REPLACE FUNCTION insert_nickname (
    param_nickname CHARACTER VARYING(19))
    RETURNS INTEGER AS $$
DECLARE
  result INTEGER;
BEGIN
  SELECT nickname_id
  INTO result
  FROM nickname
  WHERE nickname = param_nickname;
  IF result IS NULL THEN
    INSERT INTO nickname(nickname_id, nickname)
    VALUES (DEFAULT, param_nickname)
    RETURNING nickname_id INTO result;
  END IF;
  RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Insert the given date as well as the given combination of date, hex-encoded
-- /24 IP address prefix, and fingerprint identifier into the date_address24
-- table, if they're not yet contained. Return the number of inserted rows,
-- which is 2 if the given date did not exist in the date_address24 table yet, 1
-- if the date existed but not in combination with the given address prefix and
-- fingerprint identifier, or 0 if both date and combination already existed.
CREATE OR REPLACE FUNCTION insert_date_address24 (
    insert_date DATE,
    insert_address24 CHARACTER(6),
    insert_fingerprint_id INTEGER)
    RETURNS INTEGER AS $$
  DECLARE
    existing_rows INTEGER;
  BEGIN
    SELECT COUNT(*)
        INTO existing_rows
        FROM date_address24
        WHERE date = insert_date
        AND (address24 IS NULL OR address24 = insert_address24)
        AND (fingerprint_id IS NULL
             OR fingerprint_id = insert_fingerprint_id);
    IF existing_rows < 2 THEN
      IF existing_rows < 1 THEN
        INSERT INTO date_address24 (date, address24, fingerprint_id)
        VALUES (insert_date, NULL, NULL);
      END IF;
      INSERT INTO date_address24 (date, address24, fingerprint_id)
      VALUES (insert_date, insert_address24, insert_fingerprint_id);
      RETURN 2 - existing_rows;
    ELSE
      RETURN 0;
    END IF;
  END;
$$ LANGUAGE 'plpgsql';

-- Insert a status entry into the statusentry_oraddress table. First check that
-- this status entry isn't contained in the table yet. It's okay to insert the
-- same status entry multiple times for different IP addresses though. Return
-- the number of inserted rows as result.
CREATE OR REPLACE FUNCTION insert_statusentry_oraddress (
    insert_validafter TIMESTAMP WITHOUT TIME ZONE,
    insert_fingerprint_base64 CHARACTER(27),
    insert_oraddress TEXT,
    insert_oraddress24 CHARACTER(6),
    insert_nickname_param CHARACTER VARYING(19),
    insert_exit BOOLEAN)
    RETURNS INTEGER AS $$
  DECLARE
    insert_fingerprint_id INTEGER;
    insert_nickname_id INTEGER;
  BEGIN
    insert_fingerprint_id :=
        insert_fingerprint(insert_fingerprint_base64);
    IF (SELECT COUNT(*)
        FROM statusentry_oraddress
        WHERE validafter = insert_validafter
        AND fingerprint_id = insert_fingerprint_id
        AND oraddress = insert_oraddress::INET) = 0 THEN
      insert_nickname_id := insert_nickname(insert_nickname_param);
      INSERT INTO statusentry_oraddress (validafter, fingerprint_id,
            oraddress, nickname_id, exit)
          VALUES (insert_validafter, insert_fingerprint_id,
            insert_oraddress::INET, insert_nickname_id,
            insert_exit);
      RETURN 1 + insert_date_address24(DATE(insert_validafter),
                 insert_oraddress24, insert_fingerprint_id);
    ELSE
      RETURN 0;
    END IF;
  END;
$$ LANGUAGE 'plpgsql';

-- Insert an exit list entry into the exitlistentry_exitaddress table. Check
-- that this entry hasn't been inserted before. It's okay to insert the same
-- exit list entry multiple times for different exit addresses. Return the
-- number of inserted rows as result.
CREATE OR REPLACE FUNCTION insert_exitlistentry_exitaddress (
    insert_fingerprint_base64 CHARACTER(27),
    insert_exitaddress TEXT,
    insert_exitaddress24 CHARACTER(6),
    insert_scanned TIMESTAMP WITHOUT TIME ZONE)
    RETURNS INTEGER AS $$
  DECLARE
    insert_fingerprint_id INTEGER;
  BEGIN
    insert_fingerprint_id := insert_fingerprint(insert_fingerprint_base64);
    IF (SELECT COUNT(*)
        FROM exitlistentry_exitaddress
        WHERE fingerprint_id = insert_fingerprint_id
        AND exitaddress = insert_exitaddress::INET
        AND scanned = insert_scanned) = 0 THEN
      INSERT INTO exitlistentry_exitaddress (fingerprint_id, exitaddress,
          scanned) VALUES (insert_fingerprint_id, insert_exitaddress::INET,
          insert_scanned);
      RETURN 1 + insert_date_address24(DATE(insert_scanned),
                 insert_exitaddress24, insert_fingerprint_id);
    ELSE
      RETURN 0;
    END IF;
  END;
$$ LANGUAGE 'plpgsql';

-- Search for (1) status entries with an IPv4 or IPv6 onion routing address in
-- the same /24 network as the given hex-encoded IP address prefix and with a
-- valid-after date within a day of the given date, (2) exit list entries with
-- an IPv4 exit address in the same /24 network and with a scan time not earlier
-- than two days before and not later than one day after the given date, and (3)
-- the last and first dates in the database as well as the dates for which the
-- database contains relevant data within a day of the given date.
--
-- This function makes heavy use of the date_address24 table in order to reduce
-- query response time by first obtaining all relevant fingerprint identifiers.
-- In the next step it runs three selects to obtain status entries, exit list
-- entries, and relevant dates. Any postprocessing, including filtering by exact
-- IP address or matching status entries and exit list entries, needs to happen
-- at the caller.
CREATE OR REPLACE FUNCTION search_by_date_address24 (
  search_date DATE, search_address24 CHARACTER(6))
    RETURNS TABLE(
      date DATE,
      fingerprint_base64 CHARACTER(27),
      scanned TIMESTAMP WITHOUT TIME ZONE,
      exitaddress INET,
      validafter TIMESTAMP WITHOUT TIME ZONE,
      nickname CHARACTER VARYING(19),
      exit BOOLEAN,
      oraddress INET) AS $$
  BEGIN
  RETURN QUERY EXECUTE
     'WITH matching_fingerprint_ids AS (
          SELECT fingerprint_id FROM date_address24
          WHERE date_address24.date >= $1 - 2
          AND date_address24.date <= $1 + 1
          AND date_address24.address24 = $2)
     SELECT NULL::DATE AS date, fingerprint_base64, scanned, exitaddress,
            NULL AS validafter, NULL AS nickname, NULL AS exit,
            NULL AS oraddress
     FROM exitlistentry_exitaddress
     NATURAL JOIN fingerprint
     WHERE DATE(exitlistentry_exitaddress.scanned) >= $1 - 2
     AND DATE(exitlistentry_exitaddress.scanned) <= $1 + 1
     AND exitlistentry_exitaddress.fingerprint_id
         IN (SELECT fingerprint_id FROM matching_fingerprint_ids)
     UNION
     SELECT NULL::DATE AS date, fingerprint_base64, NULL AS scanned,
            NULL AS exitaddress, validafter, nickname, exit,
            oraddress
     FROM statusentry_oraddress
     NATURAL JOIN fingerprint
     NATURAL JOIN nickname
     WHERE DATE(statusentry_oraddress.validafter) >= $1 - 1
     AND DATE(statusentry_oraddress.validafter) <= $1 + 1
     AND statusentry_oraddress.fingerprint_id
         IN (SELECT fingerprint_id FROM matching_fingerprint_ids)
     UNION
     SELECT date, NULL AS fingerprint_base64, NULL AS scanned,
            NULL AS exitaddress, NULL AS validafter, NULL AS nickname,
            NULL AS exit, NULL AS oraddress
     FROM date_address24
     WHERE date IN (SELECT MIN(date) FROM date_address24 UNION
                    SELECT MAX(date) FROM date_address24 UNION
                    SELECT date FROM date_address24
                    WHERE date >= $1 - 1 AND date <= $1 + 1)'
    USING search_date, search_address24;
END;
$$ LANGUAGE plpgsql;

-- Migrate from the earlier schema in exonerator.sql to this schema. This
-- migration happens in two big loops, one over statusentry and one over
-- exitlistentry, in which entries are copied to statusentry_oraddress and
-- exitlistentry_exitaddress, respectively. Entries in both loops are ordered by
-- fingerprint and by timestamp in order to reduce insert attempts into the
-- fingerprint, nickname, and date_address24 tables as much as possible. This
-- function can easily run for days, which is why it prints out a few dozen
-- progress messages while copying rows. This function is only run once and
-- deleted further down below.
CREATE OR REPLACE FUNCTION migrate_from_exonerator_sql()
    RETURNS INTEGER AS $$
DECLARE
  existing_rows BIGINT;
  copied_rows BIGINT := 0;
  last_printed_progress BIGINT := 0;
  last_nickname TEXT := NULL;
  last_nickname_id INTEGER;
  last_fingerprint_base64 TEXT := NULL;
  last_fingerprint_id INTEGER;
  last_address24 TEXT := NULL;
  last_date DATE := NULL;
  encoded_rawstatusentry TEXT;
  exit BOOLEAN;
  rec RECORD;
  matches TEXT[];
  oraddress24 CHARACTER(6);
  fingerprint_base64 TEXT;
BEGIN
  RAISE NOTICE '% Starting schema migration.', timeofday();
  SELECT COUNT(*) INTO existing_rows FROM statusentry;
  RAISE NOTICE '% Sorting % rows in statusentry (this may take days!).',
        timeofday(), existing_rows;
  FOR rec IN SELECT * FROM statusentry ORDER BY fingerprint, validafter
  LOOP
    IF copied_rows = 0 THEN
      RAISE NOTICE '% Query returned, starting to copy.', timeofday();
    END IF;
    encoded_rawstatusentry := ENCODE(rec.rawstatusentry, 'escape');
    matches := regexp_matches(encoded_rawstatusentry, '^r (\S+) (\S+) ');
    IF last_nickname IS NULL OR matches[1] != last_nickname THEN
      last_nickname_id := insert_nickname(matches[1]);
    END IF;
    IF last_fingerprint_base64 IS NULL
       OR matches[2] != last_fingerprint_base64 THEN
      last_fingerprint_id := insert_fingerprint(matches[2]);
    END IF;
    IF encoded_rawstatusentry ~ 'p (\S+ [\d\-,]+)' THEN
      exit := encoded_rawstatusentry !~ 'p reject 1-65535';
    ELSE
      exit := NULL;
    END IF;
    INSERT INTO statusentry_oraddress (validafter, fingerprint_id,
          oraddress, nickname_id, exit)
        VALUES (rec.validafter, last_fingerprint_id, rec.oraddress,
                last_nickname_id, exit);
    IF rec.oraddress24 IS NOT NULL THEN
      oraddress24 := rec.oraddress24;
    ELSIF rec.oraddress48 IS NOT NULL THEN
      oraddress24 := SUBSTRING(rec.oraddress48, 1, 6);
    ELSE
      RAISE EXCEPTION 'Invalid statusentry row: %, %, %.',
            rec.validafter, rec.fingerprint, rec.oraddress;
    END IF;
    IF last_fingerprint_base64 IS NULL
       OR matches[2] != last_fingerprint_base64
       OR last_address24 IS NULL OR oraddress24 != last_address24
       OR last_date IS NULL OR DATE(rec.validafter) != last_date THEN
      PERFORM insert_date_address24(DATE(rec.validafter), oraddress24,
         last_fingerprint_id);
      last_address24 := oraddress24;
      last_date := DATE(rec.validafter);
    END IF;
    last_nickname := matches[1];
    last_fingerprint_base64 := matches[2];
    copied_rows := copied_rows + 1;
    IF copied_rows - last_printed_progress > existing_rows / 50 THEN
      RAISE NOTICE '% Copied % rows from statusentry.',
            timeofday(), copied_rows;
      last_printed_progress := copied_rows;
    END IF;
  END LOOP;
  last_nickname := NULL;
  last_fingerprint_base64 := NULL;
  last_address24 := NULL;
  last_date := NULL;
  SELECT COUNT(*) INTO existing_rows FROM exitlistentry;
  copied_rows := 0;
  last_printed_progress := 0;
  RAISE NOTICE '% Sorting % rows in exitlistentry (this may take hours!).',
        timeofday(), existing_rows;
  FOR rec IN SELECT * FROM exitlistentry
    ORDER BY fingerprint, DATE(scanned)
  LOOP
    IF copied_rows = 0 THEN
      RAISE NOTICE '% Query returned, starting to copy.', timeofday();
    END IF;
    fingerprint_base64 := SUBSTRING(ENCODE(DECODE(rec.fingerprint, 'hex'),
                          'base64'), 1, 27);
    IF last_fingerprint_base64 IS NULL
       OR fingerprint_base64 != last_fingerprint_base64 THEN
      last_fingerprint_id := insert_fingerprint(fingerprint_base64);
    END IF;
    INSERT INTO exitlistentry_exitaddress (fingerprint_id, exitaddress,
      scanned) VALUES (last_fingerprint_id, rec.exitaddress, rec.scanned);
    IF last_fingerprint_base64 IS NULL
       OR fingerprint_base64 != last_fingerprint_base64
       OR last_address24 IS NULL OR rec.exitaddress24 != last_address24
       OR last_date IS NULL OR DATE(rec.scanned) != last_date THEN
      PERFORM insert_date_address24(DATE(rec.scanned), rec.exitaddress24,
          last_fingerprint_id);
      last_address24 := rec.exitaddress24;
      last_date := DATE(rec.scanned);
    END IF;
    last_fingerprint_base64 := fingerprint_base64;
    copied_rows := copied_rows + 1;
    IF copied_rows - last_printed_progress > existing_rows / 5 THEN
      RAISE NOTICE '% Copied % rows from exitlistentry.',
            timeofday(), copied_rows;
      last_printed_progress := copied_rows;
    END IF;
  END LOOP;
  RAISE NOTICE '% Completed schema migration.', timeofday();
RETURN 1;
END;
$$ LANGUAGE plpgsql;

-- Run the migration script once. This is the only time this function is run
-- before it's dropped further down below.
SELECT migrate_from_exonerator_sql();

-- Create an index on date and first three address bytes which is supposed to be
-- the main index used for lookups.
CREATE INDEX date_address24_date_address24
    ON date_address24 (date, address24);

-- Create an index on statusentry_oraddress for joining with date_address24 as
-- part of search_by_date_address24.
CREATE INDEX statusentry_oraddress_date_validafter_fingerprint_id
    ON statusentry_oraddress (DATE(validafter), fingerprint_id);

-- Create an index on exitlistentry_exitaddress for joining with date_address24
-- as part of search_by_date_address24.
CREATE INDEX exitlistentry_exitaddress_date_scanned_fingerprint_id
    ON exitlistentry_exitaddress (DATE(scanned), fingerprint_id);

-- Drop the migration function.
DROP FUNCTION migrate_from_exonerator_sql();

-- Drop the old insert_* and search_* functions which are based on the old
-- statusentry and exitlistentry tables.
DROP FUNCTION insert_exitlistentry(
  CHARACTER, CHARACTER, TEXT, TIMESTAMP WITHOUT TIME ZONE, BYTEA);
DROP FUNCTION insert_statusentry(
  TIMESTAMP WITHOUT TIME ZONE, CHARACTER, CHARACTER, CHARACTER, CHARACTER,
  TEXT, BYTEA);
DROP FUNCTION search_by_address24_date(TEXT, DATE);
DROP FUNCTION search_by_address48_date(TEXT, DATE);

-- Also drop the old tables including any indexes on them.
DROP TABLE exitlistentry CASCADE;
DROP TABLE statusentry CASCADE;

