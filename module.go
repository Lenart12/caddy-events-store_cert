package store_cert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/certmagic"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements an event handler that stores the cert to a bucket.
// By default, the bucket is assumed to be a local directory.
// The handler can be configured to include or exclude specific certificates.
type Handler struct {
	// The URL of the bucket where the certificates are stored.
	// See https://gocloud.dev/howto/blob/#services for more information.
	// If no schema is specified, file:// is assumed.
	// Example: "s3://my-bucket-name", "file:///path/to/directory" (same as "/path/to/directory")
	BucketURL string `json:"bucket_url,omitempty"`

	// Certificates to include from the store. If empty, all certificates are included.
	IncludedCertificates []string `json:"include_cert,omitempty"`

	// Certificates to exclude from the store. If empty, no certificates are excluded.
	ExcludedCertificates []string `json:"exclude_cert,omitempty"`

	// If true, the handler will continue to the "after" handler even if the certificate is excluded.
	ContinueExcluded bool `json:"continue_excluded,omitempty"`

	// If true, the handler will continue to the "after" handler even if an error during storage occurs.
	ContinueOnError bool `json:"continue_on_errors,omitempty"`

	// The handler to execute after the certificate is stored.
	AfterRaw json.RawMessage `json:"after,omitempty" caddy:"namespace=events.handlers inline_key=handler"`

	after caddyevents.Handler

	// Cached set of accepted certificates to avoid recalculating inclusion/exclusion.
	acceptedCerts map[string]bool

	// Caddy storage instance.
	storage certmagic.Storage

	// The bucket where the certificates are stored. This is set during provisioning.
	bucket *blob.Bucket

	// Logger for this handler.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.store_cert",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (eh *Handler) Provision(ctx caddy.Context) error {
	eh.logger = ctx.Logger(eh)
	eh.storage = ctx.Storage()

	if eh.IncludedCertificates == nil {
		eh.IncludedCertificates = []string{}
	}

	if eh.ExcludedCertificates == nil {
		eh.ExcludedCertificates = []string{}
	}

	if eh.BucketURL == "" {
		return errors.New("missing bucket URL")
	}

	parsed_url, err := url.Parse(eh.BucketURL)
	if err != nil {
		return errors.Wrap(err, "failed to parse bucket URL")
	}

	if parsed_url.Scheme == "file" || parsed_url.Scheme == "" {
		// Make sure the scheme is set to file
		parsed_url.Scheme = "file"

		// Implied relative path
		if parsed_url.Host == "" && !strings.HasPrefix(parsed_url.Path, "/") && !strings.HasPrefix(parsed_url.Path, ".") {
			parsed_url.Host = "."
		}

		query, err := url.ParseQuery(parsed_url.RawQuery)
		if err != nil {
			return errors.Wrap(err, "failed to parse bucket url query")
		}

		set_query := func(key, value string) {
			if !query.Has(key) {
				query.Set(key, value)
			}
		}

		// Default options for fileblob (can be overridden by query parameters)
		set_query("create_dir", "true")
		set_query("dir_file_mode", fmt.Sprint(0o700)) // Must be formatted as decimal
		set_query("no_tmp_dir", "true")
		set_query("metadata", "skip")
		parsed_url.RawQuery = query.Encode()

		eh.BucketURL = parsed_url.String()
		eh.logger.Debug("Normalized bucket URL", zap.String("bucket_url", eh.BucketURL))
	}

	bucket, err := blob.OpenBucket(ctx, eh.BucketURL)
	if err != nil {
		return errors.Wrap(err, "failed to open bucket")
	}
	eh.bucket = bucket

	if eh.AfterRaw != nil {
		afterHandlerIface, err := ctx.LoadModule(eh, "AfterRaw")
		if err != nil {
			return errors.Wrap(err, "failed to load after module")
		}
		eh.after = afterHandlerIface.(caddyevents.Handler)
	}

	return nil
}

// Validate ensures the module is properly configured.
func (eh *Handler) Validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if accessible, err := eh.bucket.IsAccessible(ctx); err != nil || !accessible {
		if err != nil {
			return errors.Wrap(err, "failed to check bucket accessibility")
		}
		return errors.New("bucket is not accessible")
	}

	return nil
}

func (eh *Handler) acceptCert(certName string) bool {
	if eh.acceptedCerts == nil {
		eh.acceptedCerts = make(map[string]bool)
	}

	if accepted, ok := eh.acceptedCerts[certName]; ok {
		return accepted
	}

	// Default to accepting the certificate if no inclusion rules are set
	eh.acceptedCerts[certName] = len(eh.IncludedCertificates) == 0

	// TODO: Wildcard matching, for now just exact match
	for _, includedCert := range eh.IncludedCertificates {
		if certName == includedCert {
			eh.acceptedCerts[certName] = true
		}
	}

	for _, excludedCert := range eh.ExcludedCertificates {
		if certName == excludedCert {
			eh.acceptedCerts[certName] = false
		}
	}
	return eh.acceptedCerts[certName]
}

// Handle handles the event.
func (eh *Handler) Handle(ctx context.Context, e caddyevents.Event) error {
	if e.Name() != "cert_obtained" {
		eh.logger.Warn("store_cert should only be handled on `cert_obtained`, ignoring", zap.String("event", e.Name()))
		return nil
	}

	cert_id, ok := e.Data["identifier"].(string)
	if !ok {
		return errors.New("missing certificate identifier")
	}

	is_accepted := eh.acceptCert(cert_id)
	if !is_accepted {
		eh.logger.Debug("Certificate is excluded", zap.String("cert_id", cert_id))
		if eh.after != nil && !eh.ContinueExcluded {
			eh.logger.Debug("Aborting handler due to exclusion")
			return nil
		}
	}

	upload_files := func() error { return nil }

	if is_accepted {
		eh.logger.Info("Storing certificate", zap.String("cert_id", cert_id))

		private_key_path, ok := e.Data["private_key_path"].(string)
		if !ok {
			return errors.New("missing private key path")
		}
		certificate_path, ok := e.Data["certificate_path"].(string)
		if !ok {
			return errors.New("missing certificate path")
		}
		metadata_path, ok := e.Data["metadata_path"].(string)
		if !ok {
			return errors.New("missing metadata path")
		}

		opts := &blob.WriterOptions{
			ContentType: "application/octet-stream",
		}

		upload_to_bucket := func(filename string) error {
			key := cert_id + "/" + path.Base(filename)
			file_bytes, err := eh.storage.Load(ctx, filename)
			if err != nil {
				return errors.Wrap(err, "failed to load file")
			}
			eh.logger.Debug("Uploading file to bucket", zap.String("key", key), zap.Int("size", len(file_bytes)))

			return eh.bucket.Upload(ctx, key, bytes.NewReader(file_bytes), opts)
		}

		upload_files = func() error {
			for _, filename := range []string{private_key_path, certificate_path, metadata_path} {
				if err := upload_to_bucket(filename); err != nil {
					return err
				}
			}
			return nil
		}
	}

	go func() {
		if err := upload_files(); err != nil {
			eh.logger.Error("Failed to upload files to bucket", zap.Error(err))
			if !eh.ContinueOnError {
				return
			}
		}

		if eh.after != nil {
			if err := eh.after.Handle(ctx, e); err != nil {
				eh.logger.Error("Failed to handle event in after handler", zap.Error(err))
				return
			}
		}
	}()

	return nil
}

// UnmarshalCaddyfile parses the module's Caddyfile config. Syntax:
//
//	store_cert [<bucket_url>] [<include_cert...>] {
//		bucket_url			<bucket_url>
//		include_cert		<include_cert...>
//		exclude_cert		<exclude_cert...>
//		continue_excluded	<bool>
//		after				<handler>
//	}
func (eh *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	fmt.Printf("Unmarshal eh=%p\n", eh)
	for d.Next() {
		if d.NextArg() {
			eh.BucketURL = d.Val()
		}
		for d.NextArg() {
			eh.IncludedCertificates = append(eh.IncludedCertificates, d.Val())
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "bucket_url":
				if eh.BucketURL != "" {
					return d.Err("bucket_url already set")
				}
				if d.NextArg() {
					eh.BucketURL = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "include_cert":
				for d.NextArg() {
					eh.IncludedCertificates = append(eh.IncludedCertificates, d.Val())
				}
			case "exclude_cert":
				for d.NextArg() {
					eh.ExcludedCertificates = append(eh.ExcludedCertificates, d.Val())
				}
			case "continue_excluded":
				if !d.NextArg() {
					return d.ArgErr()
				}
				abort, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("parsing continue_excluded: %v", err)
				}
				eh.ContinueExcluded = abort
				if d.NextArg() {
					return d.ArgErr()
				}
			case "continue_on_errors":
				if !d.NextArg() {
					return d.ArgErr()
				}
				abort, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("parsing continue_on_errors: %v", err)
				}
				eh.ContinueOnError = abort
				if d.NextArg() {
					return d.ArgErr()
				}
			case "after":
				if !d.NextArg() {
					return d.ArgErr()
				}
				handlerName := d.Val()
				modID := "events.handlers." + handlerName
				unm, err := caddyfile.UnmarshalModule(d, modID)
				if err != nil {
					return err
				}

				eh.AfterRaw = caddyconfig.JSONModuleObject(unm, "handler", handlerName, nil)
			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}
	if eh.BucketURL == "" {
		return d.Err("missing bucket URL")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddy.Validator       = (*Handler)(nil)
	_ caddyevents.Handler   = (*Handler)(nil)
)
