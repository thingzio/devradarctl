package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/client"
	"github.com/thingzio/devradarctl/internal/sbom"
)

func submitCmd() *cli.Command {
	return &cli.Command{
		Name:      "submit",
		Usage:     "Submit an SBOM to DevRadar (from a file or generated from an image)",
		ArgsUsage: " ",
		Description: "Provide exactly one of --file or --image.\n" +
			"  --file: base64-encode and submit an existing SBOM (optionally set --image-ref).\n" +
			"  --image: resolve the digest, generate an all-layers SBOM, then submit it.\n\n" +
			"The API token is read from DEVRADAR_TOKEN, or from stdin when piped.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{
				Name:    flagFile,
				Aliases: []string{"f", "sbom"},
				Usage:   "path to an existing SBOM file to submit",
			},
			&cli.StringFlag{
				Name:    flagImage,
				Aliases: []string{"i"},
				Usage:   "container image reference to generate an SBOM from and submit",
			},
			&cli.StringFlag{
				Name:  flagImageRef,
				Usage: "digest-pinned image reference override (repo@sha256:…), file mode only",
			},
			&cli.StringFlag{
				Name:  flagTag,
				Usage: "human version tag to record (e.g. v1.20.2); defaults to the image's tag",
			},
			&cli.StringSliceFlag{
				Name:    flagLabel,
				Usage:   "grouping label(s) to attach; repeatable",
				Sources: cli.EnvVars("DEVRADAR_LABELS"),
			},
			&cli.StringFlag{
				Name:    flagBaseURL,
				Usage:   "DevRadar service base URL",
				Value:   client.DefaultBaseURL,
				Sources: cli.EnvVars("DEVRADAR_BASE_URL"),
			},
		}, syftFlags()...),
		Action: runSubmit,
	}
}

func runSubmit(ctx context.Context, c *cli.Command) error {
	file := c.String(flagFile)
	image := c.String(flagImage)
	switch {
	case file == "" && image == "":
		return errors.New("one of --file or --image is required")
	case file != "" && image != "":
		return errors.New("--file and --image are mutually exclusive")
	}

	token, err := resolveToken(c.Reader)
	if err != nil {
		return err
	}

	req := client.SubmitRequest{
		Labels:  c.StringSlice(flagLabel),
		Version: c.String(flagTag),
	}

	if file != "" {
		doc, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read SBOM file: %w", err)
		}
		req.SBOM = doc
		req.ImageRef = c.String(flagImageRef)
	} else {
		res, err := generateSBOM(ctx, image, sbom.Options{
			SyftPath: c.String(flagSyftPath),
			Scope:    c.String(flagScope),
		})
		if err != nil {
			return err
		}
		req.SBOM = res.Doc
		req.ImageRef = res.Ref
		// Preserve the human tag the digest replaced unless overridden.
		if req.Version == "" {
			req.Version = sbom.Tag(image)
		}
	}

	cl := client.New(c.String(flagBaseURL), token)
	resp, err := cl.Submit(ctx, req)
	if err != nil {
		return err
	}

	slog.Debug("submitted", "sbom_id", resp.SBOMID, "digest", resp.Digest, "existing", resp.Existing)
	if resp.Existing {
		fmt.Printf("SBOM already present: id=%s format=%s image_ref=%s\n", resp.SBOMID, resp.Format, resp.ImageRef)
	} else {
		fmt.Printf("SBOM submitted: id=%s format=%s image_ref=%s\n", resp.SBOMID, resp.Format, resp.ImageRef)
	}
	return nil
}

// resolveToken returns the API token from DEVRADAR_TOKEN, or from stdin when it
// is piped (not a terminal). It errors if neither yields a token.
func resolveToken(stdin io.Reader) (string, error) {
	if tok := strings.TrimSpace(os.Getenv("DEVRADAR_TOKEN")); tok != "" {
		return tok, nil
	}
	if piped(stdin) {
		raw, err := io.ReadAll(io.LimitReader(stdin, 1<<16))
		if err != nil {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		if tok := strings.TrimSpace(string(raw)); tok != "" {
			return tok, nil
		}
	}
	return "", errors.New("no API token: set DEVRADAR_TOKEN or pipe it via stdin")
}

// piped reports whether r is a non-terminal stdin (i.e. has piped/redirected
// data). A nil reader or an *os.File that is a character device (a TTY) is not
// considered piped.
func piped(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return r != nil
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}
