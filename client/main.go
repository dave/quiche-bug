// Reproducer client for the quiche pkt_num_len bug.
//
// Hits the test server (which runs Cloudflare's quiche with kernel-level
// outbound packet reordering) over HTTP/3, then scans qlog for
// payload_decrypt_error events.
//
//   go run . --url=https://<server>:4443
//
// On stock quiche the run reports a non-zero AEAD failure count. With the
// .max(2) patch applied to quiche::packet::pkt_num_len, the count is zero.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
)

func main() {
	var (
		serverURL = flag.String("url", "https://127.0.0.1:4443", "server base URL (https://host:port)")
		workers   = flag.Int("workers", 8, "concurrent workers sharing one QUIC connection")
		duration  = flag.Duration("duration", 2*time.Minute, "test duration")
		bodySize  = flag.Int("size", 30720, "response size — server returns this many random bytes")
		qlogDir   = flag.String("qlog", "qlog", "qlog output directory (empty disables)")
	)
	flag.Parse()

	if *qlogDir != "" {
		if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
			log.Fatalf("mkdir %s: %v", *qlogDir, err)
		}
		_ = os.Setenv("QLOGDIR", *qlogDir)
		log.Printf("qlog dir: %s", *qlogDir)
	}

	h3 := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  90 * time.Second,
			KeepAlivePeriod: 25 * time.Second,
			Tracer:          qlog.DefaultConnectionTracer,
		},
	}
	defer h3.Close()

	client := &http.Client{
		Transport: h3,
		Timeout:   30 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("interrupted, shutting down")
		cancel()
	}()

	var sent, completed, failed int64

	log.Printf("starting %d workers against %s for %s", *workers, *serverURL, *duration)
	start := time.Now()

	statTicker := time.NewTicker(30 * time.Second)
	defer statTicker.Stop()
	statDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(statDone)
				return
			case <-statTicker.C:
				log.Printf("t+%.0fs sent=%d completed=%d failed=%d",
					time.Since(start).Seconds(),
					atomic.LoadInt64(&sent),
					atomic.LoadInt64(&completed),
					atomic.LoadInt64(&failed))
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			for ctx.Err() == nil {
				n := rng.Int63()
				url := fmt.Sprintf("%s/stream-bytes/%d?n=%d", *serverURL, *bodySize, n)
				atomic.AddInt64(&sent, 1)
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						atomic.AddInt64(&failed, 1)
					}
					continue
				}
				_, copyErr := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if copyErr != nil {
					if ctx.Err() == nil {
						atomic.AddInt64(&failed, 1)
					}
					continue
				}
				atomic.AddInt64(&completed, 1)
			}
		}(w)
	}

	wg.Wait()
	<-statDone

	finalSent := atomic.LoadInt64(&sent)
	finalCompleted := atomic.LoadInt64(&completed)
	finalFailed := atomic.LoadInt64(&failed)
	log.Printf("done after %s — sent=%d completed=%d failed=%d",
		time.Since(start).Round(time.Second), finalSent, finalCompleted, finalFailed)

	if *qlogDir != "" {
		scanQlog(*qlogDir, start)
	}
}

// scanQlog walks the qlog directory and reports payload_decrypt_error
// counts. The server's pkt_num_len behaviour is the only quic-go-visible
// signal that distinguishes patched from unpatched quiche on this code path.
func scanQlog(dir string, runStart time.Time) {
	files, err := filepath.Glob(filepath.Join(dir, "*.sqlog"))
	if err != nil {
		log.Printf("qlog scan error: %v", err)
		return
	}
	if len(files) == 0 {
		log.Printf("qlog scan: no .sqlog files found in %s", dir)
		return
	}
	needle := []byte("payload_decrypt_error")
	var totalAEAD int
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil || info.ModTime().Before(runStart) {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		count := bytes.Count(data, needle)
		if count > 0 {
			log.Printf("qlog %s: %d payload_decrypt_error events", filepath.Base(f), count)
			totalAEAD += count
		}
	}
	log.Printf("=== AEAD failure total: %d ===", totalAEAD)
	if totalAEAD == 0 {
		log.Printf("PASS — no AEAD decryption errors observed")
	} else {
		log.Printf("FAIL — server emitted packet numbers that the client could not decode")
		log.Printf("       (this is the quiche pkt_num_len 1-byte truncation bug)")
		os.Exit(1)
	}
}
