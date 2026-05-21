# azul-plugin-opencti-feed

Azul batch plugin for reading file-hash indicators from OpenCTI and ingesting them into Azul as mapped binary events.

This is the feed-side companion to `azul-plugin-opencti`: instead of checking one Azul binary against OpenCTI, it reads
OpenCTI indicators and publishes matching binary metadata into Azul using the same dispatcher/status-event pattern as
`AustralianCyberSecurityCentre/azul-plugin-report-feeds`.

## Features

- Pages through OpenCTI indicators with direct GraphQL requests over `httpx`
- Extracts `SHA-256`, `SHA-1`, and `MD5` values from STIX file-hash indicator patterns
- Publishes SHA-256 indicators as Azul `mapped` binary events
- Adds OpenCTI indicator metadata as Azul features:
  - `cti_indicator_id`
  - `cti_indicator_name`
  - `cti_indicator_pattern`
  - `cti_description`
  - `cti_score`
  - `cti_confidence`
  - `cti_label`
  - `cti_external_reference`
- Stores the newest processed OpenCTI `updated_at` timestamp in a local state directory for incremental runs

Indicators without a SHA-256 are skipped because Azul mapped binary events need a stable SHA-256 entity key.

## Configuration

Required:

- `opencti_url`: OpenCTI base URL, for example `https://opencti.example`
- `opencti_token`: OpenCTI API token

Optional:

- `opencti_publisher`: Publisher name used for the Azul multiplugin author. Default: `OpenCTI`
- `page_size`: Number of OpenCTI indicators to request per GraphQL page. Default: `100`
- `request_timeout`: HTTP request timeout in seconds. Default: `30`
- `api_retry_count`: Number of HTTP transport retries. Default: `3`
- `state_directory`: Directory where the last processed timestamp is stored. Default: `~/.opencti-feed`
- `feed_source_name`: Azul source name. Default: `opencti`
- `feed_security`: Source security marking. Default: `OFFICIAL`
- `namespace_suffix`: Optional suffix for namespaced deployments

## Running

```powershell
azul-plugin-opencti-feed `
  --server https://azul.example `
  -c opencti_url https://opencti.example `
  -c opencti_token <token>
```
