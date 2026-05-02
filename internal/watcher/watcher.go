// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package watcher implements the background polling orchestrator that watches
// the CA database for new certificates and revocations, appends them to the
// issuance log, and creates periodic checkpoints.
package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/cadb"
	"github.com/briantrzupek/ca-extension-merkle/internal/issuancelog"
	"github.com/briantrzupek/ca-extension-merkle/internal/revocation"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Config holds watcher configuration.
type Config struct {
	PollInterval           time.Duration
	CheckpointInterval     time.Duration
	BatchSize              int
	RevocationPollInterval time.Duration
	// Housekeeping settings.
	HousekeepingInterval time.Duration // How often to run cleanup (0 = disabled).
	StaleBundleRetention time.Duration // Delete stale assertion bundles older than this.
	CheckpointRetention  time.Duration // Delete non-landmark checkpoints older than this.
	CheckpointKeepRecent int           // Always keep at least this many recent checkpoints.
	EventRetention       time.Duration // Delete events older than this.
	EventKeepRecent      int           // Always keep at least this many recent events.
}

// CheckpointCallback is called after a new checkpoint is created.
// It receives the checkpoint ID and tree size.
type CheckpointCallback func(ctx context.Context, checkpointID int64, treeSize int64)

// Watcher polls the CA database and manages the issuance log.
type Watcher struct {
	cadb   *cadb.Adapter
	store  *store.Store
	log    *issuancelog.Log
	revMgr *revocation.Manager
	cfg    Config
	logger *slog.Logger

	onCheckpoint CheckpointCallback

	mu              sync.Mutex
	running         bool
	lastCheckpoint  time.Time
	certsProcessed  int64
	revocsProcessed int64
}

// New creates a new Watcher.
func New(
	ca *cadb.Adapter,
	s *store.Store,
	ilog *issuancelog.Log,
	revMgr *revocation.Manager,
	cfg Config,
	logger *slog.Logger,
) *Watcher {
	return &Watcher{
		cadb:   ca,
		store:  s,
		log:    ilog,
		revMgr: revMgr,
		cfg:    cfg,
		logger: logger,
	}
}

// OnCheckpoint registers a callback to execute after each checkpoint.
func (w *Watcher) OnCheckpoint(fn CheckpointCallback) {
	w.onCheckpoint = fn
}

// Run starts the watcher loop. It blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()

	w.logger.Info("watcher starting",
		"poll_interval", w.cfg.PollInterval,
		"checkpoint_interval", w.cfg.CheckpointInterval,
		"batch_size", w.cfg.BatchSize,
	)

	// Initialize the log if needed.
	if err := w.log.Initialize(ctx); err != nil {
		return fmt.Errorf("watcher.Run: initialize log: %w", err)
	}

	// Emit startup event.
	_ = w.store.EmitEvent(ctx, "watcher_started", map[string]interface{}{
		"timestamp": time.Now().UTC(),
	})

	certTicker := time.NewTicker(w.cfg.PollInterval)
	defer certTicker.Stop()

	revocTicker := time.NewTicker(w.cfg.RevocationPollInterval)
	defer revocTicker.Stop()

	cpTicker := time.NewTicker(w.cfg.CheckpointInterval)
	defer cpTicker.Stop()

	// Initial poll immediately.
	if err := w.pollCertificates(ctx); err != nil {
		w.logger.Error("initial certificate poll failed", "error", err)
	}

	// Housekeeping ticker — only start if interval is configured.
	var hkTicker *time.Ticker
	var hkC <-chan time.Time
	if w.cfg.HousekeepingInterval > 0 {
		hkTicker = time.NewTicker(w.cfg.HousekeepingInterval)
		hkC = hkTicker.C
		defer hkTicker.Stop()
		w.logger.Info("housekeeping enabled",
			"interval", w.cfg.HousekeepingInterval,
			"stale_bundle_retention", w.cfg.StaleBundleRetention,
			"checkpoint_retention", w.cfg.CheckpointRetention,
			"event_retention", w.cfg.EventRetention,
		)
	}

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("watcher stopping")
			_ = w.store.EmitEvent(ctx, "watcher_stopped", map[string]interface{}{
				"timestamp":        time.Now().UTC(),
				"certs_processed":  w.certsProcessed,
				"revocs_processed": w.revocsProcessed,
			})
			return ctx.Err()

		case <-certTicker.C:
			if err := w.pollCertificates(ctx); err != nil {
				w.logger.Error("certificate poll failed", "error", err)
			}

		case <-revocTicker.C:
			if err := w.pollRevocations(ctx); err != nil {
				w.logger.Error("revocation poll failed", "error", err)
			}

		case <-cpTicker.C:
			if err := w.createCheckpoint(ctx); err != nil {
				w.logger.Error("checkpoint creation failed", "error", err)
			}

		case <-hkC:
			w.runHousekeeping(ctx)
		}
	}
}

func (w *Watcher) pollCertificates(ctx context.Context) error {
	// Standalone mode: no CA database to poll. Local-CA-issued certs are
	// appended directly via acme/finalize.go.
	if w.cadb == nil {
		return nil
	}

	// Get cursor from store.
	cursor, err := w.store.GetWatcherCursor(ctx)
	if err != nil {
		// No cursor yet — start from epoch.
		cursor = &store.WatcherCursor{
			LastCreatedAt: time.Time{},
			LastCertID:    "",
		}
	}

	certs, err := w.cadb.FetchNewCertificates(ctx, cursor.LastCreatedAt, cursor.LastCertID, w.cfg.BatchSize)
	if err != nil {
		return fmt.Errorf("watcher: fetch certs: %w", err)
	}

	if len(certs) == 0 {
		return nil
	}

	count, newSize, err := w.log.AppendCertificates(ctx, certs)
	if err != nil {
		return fmt.Errorf("watcher: append certs: %w", err)
	}

	// Update cursor to last certificate.
	last := certs[len(certs)-1]
	if err := w.store.UpdateWatcherCursor(ctx, last.CreatedDate, last.ID); err != nil {
		return fmt.Errorf("watcher: update cursor: %w", err)
	}

	w.mu.Lock()
	w.certsProcessed += int64(count)
	w.mu.Unlock()

	w.logger.Info("poll: appended certificates",
		"count", count,
		"tree_size", newSize,
		"last_id", last.ID,
	)

	_ = w.store.EmitEvent(ctx, "certificates_appended", map[string]interface{}{
		"count":     count,
		"tree_size": newSize,
		"last_id":   last.ID,
	})

	return nil
}

func (w *Watcher) pollRevocations(ctx context.Context) error {
	if w.cadb == nil {
		return nil
	}

	// Fetch ALL revoked certs from the CA database. Deduplication is handled
	// by store.AddRevocation's ON CONFLICT DO NOTHING, so re-processing
	// already-known revocations is a no-op. This eliminates the previous 24h
	// sliding window that permanently lost older revocations.
	events, err := w.cadb.FetchAllRevocations(ctx)
	if err != nil {
		return fmt.Errorf("watcher: fetch revocations: %w", err)
	}

	if len(events) == 0 {
		return nil
	}

	count, err := w.revMgr.ProcessRevocations(ctx, events)
	if err != nil {
		return fmt.Errorf("watcher: process revocations: %w", err)
	}

	w.mu.Lock()
	w.revocsProcessed += int64(count)
	w.mu.Unlock()

	if count > 0 {
		w.logger.Info("poll: processed revocations", "count", count)
	}

	return nil
}

func (w *Watcher) createCheckpoint(ctx context.Context) error {
	cp, err := w.log.CreateCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("watcher: create checkpoint: %w", err)
	}

	w.mu.Lock()
	w.lastCheckpoint = cp.Timestamp
	w.mu.Unlock()

	// Trigger assertion generation callback if registered.
	if w.onCheckpoint != nil {
		go w.onCheckpoint(ctx, cp.ID, cp.TreeSize)
	}

	return nil
}

// runHousekeeping performs periodic cleanup of stale data.
func (w *Watcher) runHousekeeping(ctx context.Context) {
	if w.cfg.StaleBundleRetention > 0 {
		deleted, err := w.store.DeleteStaleAssertionBundles(ctx, w.cfg.StaleBundleRetention)
		if err != nil {
			w.logger.Error("housekeeping: delete stale bundles", "error", err)
		} else if deleted > 0 {
			w.logger.Info("housekeeping: deleted stale assertion bundles", "count", deleted)
		}
	}

	if w.cfg.CheckpointRetention > 0 {
		deleted, err := w.store.PruneOldCheckpoints(ctx, w.cfg.CheckpointRetention, w.cfg.CheckpointKeepRecent)
		if err != nil {
			w.logger.Error("housekeeping: prune checkpoints", "error", err)
		} else if deleted > 0 {
			w.logger.Info("housekeeping: pruned old checkpoints", "count", deleted)
		}
	}

	if w.cfg.EventRetention > 0 {
		deleted, err := w.store.PruneOldEvents(ctx, w.cfg.EventRetention, w.cfg.EventKeepRecent)
		if err != nil {
			w.logger.Error("housekeeping: prune events", "error", err)
		} else if deleted > 0 {
			w.logger.Info("housekeeping: pruned old events", "count", deleted)
		}
	}
}

// Stats returns watcher runtime statistics.
type Stats struct {
	Running         bool      `json:"running"`
	CertsProcessed  int64     `json:"certs_processed"`
	RevocsProcessed int64     `json:"revocs_processed"`
	LastCheckpoint  time.Time `json:"last_checkpoint"`
}

// GetStats returns current watcher statistics.
func (w *Watcher) GetStats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		Running:         w.running,
		CertsProcessed:  w.certsProcessed,
		RevocsProcessed: w.revocsProcessed,
		LastCheckpoint:  w.lastCheckpoint,
	}
}
