# zeek-offseq-mirage

Loads the [OffSeq Mirage Feed](https://feeds.offseq.com) into the Zeek Intel framework:
handshake-verified attacker IPv4 addresses, payload URLs, malware SHA-256 hashes and attacker
user agents seen by a honeypot fleet. Matches go to `intel.log` with `sources` set to `mirage-feed`.

The feed is free, needs no API key, is published as TLP:CLEAR under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and is rebuilt daily. Listing rules,
confidence scores and the full-record formats are described in the
[feed README](https://github.com/offseq/mirage-feed).

## Install

```
zkg install zeek-offseq-mirage
```

Then add `@load packages` to `local.zeek` if it is not there yet.

## How it works

On a standalone Zeek or the cluster manager, the package:

- downloads `zeek/mirage.intel` with `curl` every 6 hours and replaces the local copy atomically,
- reads that file in `REREAD` mode, so every new copy is loaded without a restart,
- removes indicators that are no longer in the file, so addresses that age out of the feed
  (7 days after their last activity) stop matching.

The first start logs `cannot open mirage.intel` once, until the first download lands.

## Configuration

```zeek
redef OffSeqMirage::refresh_interval = 12 hrs;
redef OffSeqMirage::intel_file = "/var/lib/zeek/mirage.intel";
```

Without outbound HTTPS or `curl` on the manager, set `redef OffSeqMirage::fetch = F;` and update
`intel_file` yourself, for example from cron:

```
curl -fsS -o /var/lib/zeek/mirage.intel.tmp https://feeds.offseq.com/mirage-feed/latest/zeek/mirage.intel \
  && mv -f /var/lib/zeek/mirage.intel.tmp /var/lib/zeek/mirage.intel
```

A relative `intel_file` is resolved against Zeek's working directory. `Intel::path_prefix` does
not apply to it.

## License

MIT. The feed data is CC BY 4.0 (attribution: OffSeq Mirage Feed).
