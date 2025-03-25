# Caddy Events Store Cert Module

A Caddy module that automatically stores certificates to a bucket when they are obtained. This module is designed to work with Caddy's event system, specifically the `cert_obtained` event. This allows a consistent certificate location for use with other services or tools, even when using Caddy's automatic HTTPS switches to a
different ACME issuer.

## Features

- Store certificates to various storage backends (local filesystem, S3, GCS, Azure)
- Include or exclude specific certificates
- Chain to other event handlers after storing certificates
- Continue or stop processing on errors or excluded certificates

## Installation

To use this module, you need to build Caddy with this module included:

```sh
xcaddy build --with github.com/Lenart12/caddy-events-store_cert
```

## Configuration

### Caddyfile

```
{
  events {
    on cert_obtained store_cert [<bucket_url>] [<include_cert...>] {
      bucket_url         <bucket_url>
      include_cert       <include_cert...>
      exclude_cert       <exclude_cert...>
      continue_excluded  <bool>
      continue_on_errors <bool>
      after              <another_handler> {
        # handler config
      }
    }
  }
}
```

### JSON

```json
{
  "events": {
    "subscribe": [
      {
        "event": "cert_obtained",
        "handler": {
          "handler": "store_cert",
          "bucket_url": "s3://my-bucket-name",
          "include_cert": ["example.com"],
          "exclude_cert": ["test.example.com"],
          "continue_excluded": false,
          "continue_on_errors": false,
          "after": {
            "handler": "another_handler",
            "...": "..."
          }
        }
      }
    ]
  }
}
```

## Options

- `bucket_url`: URL of the bucket where certificates will be stored. Supports various storage backends:
  - Local filesystem: `file:///path/to/directory` or just `/path/to/directory`
  - S3: `s3://bucket-name`
  - Google Cloud Storage: `gs://bucket-name`
  - Azure Blob Storage: `azblob://container-name`

- `include_cert`: List of certificate identifiers (domains) to include. If empty, all certificates are included.

- `exclude_cert`: List of certificate identifiers to exclude. Takes precedence over inclusions.

- `continue_excluded`: Whether to continue to the "after" handler even if the certificate is excluded. Default: `false`.

- `continue_on_errors`: Whether to continue to the "after" handler even if an error occurs during storage. Default: `false`.

- `after`: Another event handler to execute after the certificate is stored.

## Buckets for cloud providers

For cloud storage backends, you need to configure credentials to access the bucket. The module uses the same environment variables as [gocloud.dev](https://gocloud.dev).

For bucket URL and authentication details, refer to the documentation [here](https://gocloud.dev/howto/blob/#services).

## Local filesystem storage across multiple file systems

> [!IMPORTANT]
> If trying to use filesystem storage across multiple file systems (such as a mounted folder in a container), make sure to use `?no_tmp_dir=true` at the end of the URL to avoid issues with temporary files.
> If you avoid this you will get errors like `rename /tmp/...: invalid cross-device link`.

## Examples

### Store all certificates to a local directory

```
{
  events {
    on cert_obtained store_cert /path/to/certs
  }
}
```

### Store all certificates to a local directory, mounted in a container

```
{
  events {
    on cert_obtained store_cert /path/to/certs?no_tmp_dir=true
  }
}
```

### Store only specific certificates to a local directory

```
{
  events {
    on cert_obtained store_cert /path/to/certs mail.example.com imap.example.com
  }
}
```

### Store all but one certificate to S3

```
{
  events {
    on cert_obtained store_cert s3://my-bucket?region=us-west-1 {
      exclude_cert test.example.com
    }
  }
}
```

### Store certificates and send a notification after

```
{
  events {
    on cert_obtained store_cert /path/to/certs {
      continue_on_errors true
      after exec curl -X POST -d "New certificate for {event.data.identifier}" https://notify.example.com
    }
  }
}
```

## Storage Structure

Certificates are stored in the bucket with the same structure as Caddy's internal storage, without the issuer. For example, a certificate for `example.com` would be stored in the following locations:

- Caddy internal storage: `certificates/{issuer}/{domain}/{domain}.crt`
- Store Cert module: `{domain}/{domain}.crt`
- Same for `{domain}/{domain}.key` and `{domain}/{domain}.json`