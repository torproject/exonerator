#!/bin/bash
rsync -arz --delete metrics.torproject.org::metrics-recent/relay-descriptors/consensuses exonerator-import/
rsync -arz --delete metrics.torproject.org::metrics-recent/relay-descriptors/server-descriptors exonerator-import/
rsync -arz --delete metrics.torproject.org::metrics-recent/exit-lists exonerator-import/
ant run | grep "\[java\]"

