package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

type config struct {
	DSN          string
	ListenAddr   string
	PollInterval time.Duration
}

func cfgFromEnv() config {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "postgres://vpnadmin:vpnadmin_central@pg-central:5432/vpndb?sslmode=disable"
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	poll := 5 * time.Second
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			poll = d
		}
	}
	return config{DSN: dsn, ListenAddr: addr, PollInterval: poll}
}

type sseClient chan []byte

type hub struct {
	register   chan sseClient
	unregister chan sseClient
	broadcast  chan []byte
}

func newHub() *hub {
	return &hub{
		register:   make(chan sseClient, 8),
		unregister: make(chan sseClient, 8),
		broadcast:  make(chan []byte, 64),
	}
}

func (h *hub) run() {
	clients := make(map[sseClient]struct{})
	for {
		select {
		case c := <-h.register:
			clients[c] = struct{}{}
		case c := <-h.unregister:
			delete(clients, c)
			close(c)
		case msg := <-h.broadcast:
			for c := range clients {
				select {
				case c <- msg:
				default:
				}
			}
		}
	}
}

func (h *hub) emit(typ string, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		log.Printf("emit marshal error: %v", err)
		return
	}
	frame := fmt.Sprintf("event: %s\ndata: %s\n\n", typ, b)
	h.broadcast <- []byte(frame)
}

// UUID PK/FK stored as string — lib/pq scans postgres UUID → Go string directly
type server struct {
	ServerID     string    `json:"server_id"`
	IP           string    `json:"ip"`
	Region       string    `json:"region"`
	RegisteredAt time.Time `json:"registered_at"`
}

type session struct {
	ID             string         `json:"id"`
	SessionID      string         `json:"session_id"`
	ServerID       string         `json:"server_id"`
	VpnIP          string         `json:"vpn_ip"`
	SessionKey     string         `json:"session_key"`
	ConnectedAt    time.Time      `json:"connected_at"`
	DisconnectedAt sql.NullTime   `json:"disconnected_at"`
}

type snapshot struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	PubIP         string    `json:"pub_ip"`
	PacketsSent   int64     `json:"packets_sent"`
	PacketsRecv   int64     `json:"packets_recv"`
	DroppedPacket int64     `json:"dropped_packet"`
	BytesTotal    int64     `json:"bytes_total"`
	RttMs         float64   `json:"rtt_ms"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type heartbeat struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	RttMs      float64   `json:"rtt_ms"`
	Success    bool      `json:"success"`
	RecordedAt time.Time `json:"recorded_at"`
}

type txLog struct {
	ID        string         `json:"id"`
	SessionID string         `json:"session_id"`
	Event     string         `json:"event"`
	Status    string         `json:"status"`
	Detail    sql.NullString `json:"detail"`
	CreatedAt time.Time      `json:"created_at"`
}

// watermarks use TIMESTAMPTZ — no BIGSERIAL to track with UUID PKs
type watermarks struct {
	snapshot  time.Time
	heartbeat time.Time
	txlog     time.Time
}

func pollLoop(ctx context.Context, db *sql.DB, h *hub, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	pushServers(ctx, db, h)
	pushSessions(ctx, db, h)
	wm := watermarks{
		snapshot:  seedSnapshots(ctx, db, h),
		heartbeat: seedHeartbeats(ctx, db, h),
		txlog:     seedTxLogs(ctx, db, h),
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pushServers(ctx, db, h)
			pushSessions(ctx, db, h)
			wm.snapshot  = pushSnapshots(ctx, db, h, wm.snapshot)
			wm.heartbeat = pushHeartbeats(ctx, db, h, wm.heartbeat)
			wm.txlog     = pushTxLogs(ctx, db, h, wm.txlog)
		}
	}
}

func pushServers(ctx context.Context, db *sql.DB, h *hub) {
	rows, err := db.QueryContext(ctx,
		`SELECT server_id, ip, region, registered_at FROM servers ORDER BY registered_at`)
	if err != nil { log.Printf("servers query: %v", err); return }
	defer rows.Close()
	var list []server
	for rows.Next() {
		var s server
		if err := rows.Scan(&s.ServerID, &s.IP, &s.Region, &s.RegisteredAt); err != nil {
			log.Printf("servers scan: %v", err); continue
		}
		list = append(list, s)
	}
	h.emit("servers", list)
}

func pushSessions(ctx context.Context, db *sql.DB, h *hub) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, server_id, vpn_ip, session_key, connected_at, disconnected_at
		 FROM sessions ORDER BY connected_at DESC`)
	if err != nil { log.Printf("sessions query: %v", err); return }
	defer rows.Close()
	var list []session
	for rows.Next() {
		var s session
		if err := rows.Scan(&s.ID, &s.SessionID, &s.ServerID, &s.VpnIP,
			&s.SessionKey, &s.ConnectedAt, &s.DisconnectedAt); err != nil {
			log.Printf("sessions scan: %v", err); continue
		}
		list = append(list, s)
	}
	h.emit("sessions", list)
}

func seedSnapshots(ctx context.Context, db *sql.DB, h *hub) time.Time {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, pub_ip, packets_sent, packets_recv,
		        dropped_packet, bytes_total, rtt_ms, recorded_at
		 FROM session_snapshots ORDER BY recorded_at DESC LIMIT 50`)
	if err != nil { log.Printf("seed snapshots: %v", err); return time.Time{} }
	defer rows.Close()
	var latest time.Time
	for rows.Next() {
		var s snapshot
		if err := rows.Scan(&s.ID, &s.SessionID, &s.PubIP, &s.PacketsSent, &s.PacketsRecv,
			&s.DroppedPacket, &s.BytesTotal, &s.RttMs, &s.RecordedAt); err != nil { continue }
		h.emit("snapshot", s)
		if s.RecordedAt.After(latest) { latest = s.RecordedAt }
	}
	return latest
}

func seedHeartbeats(ctx context.Context, db *sql.DB, h *hub) time.Time {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, rtt_ms, success, recorded_at
		 FROM heartbeats ORDER BY recorded_at DESC LIMIT 50`)
	if err != nil { log.Printf("seed heartbeats: %v", err); return time.Time{} }
	defer rows.Close()
	var latest time.Time
	for rows.Next() {
		var hb heartbeat
		if err := rows.Scan(&hb.ID, &hb.SessionID, &hb.RttMs,
			&hb.Success, &hb.RecordedAt); err != nil { continue }
		h.emit("heartbeat", hb)
		if hb.RecordedAt.After(latest) { latest = hb.RecordedAt }
	}
	return latest
}

func seedTxLogs(ctx context.Context, db *sql.DB, h *hub) time.Time {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, event, status, detail, created_at
		 FROM transaction_log ORDER BY created_at DESC LIMIT 50`)
	if err != nil { log.Printf("seed txlogs: %v", err); return time.Time{} }
	defer rows.Close()
	var latest time.Time
	for rows.Next() {
		var t txLog
		if err := rows.Scan(&t.ID, &t.SessionID, &t.Event,
			&t.Status, &t.Detail, &t.CreatedAt); err != nil { continue }
		h.emit("txlog", t)
		if t.CreatedAt.After(latest) { latest = t.CreatedAt }
	}
	return latest
}

func pushSnapshots(ctx context.Context, db *sql.DB, h *hub, after time.Time) time.Time {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, pub_ip, packets_sent, packets_recv,
		        dropped_packet, bytes_total, rtt_ms, recorded_at
		 FROM session_snapshots WHERE recorded_at > $1 ORDER BY recorded_at`, after)
	if err != nil { log.Printf("snapshots query: %v", err); return after }
	defer rows.Close()
	latest := after
	for rows.Next() {
		var s snapshot
		if err := rows.Scan(&s.ID, &s.SessionID, &s.PubIP, &s.PacketsSent, &s.PacketsRecv,
			&s.DroppedPacket, &s.BytesTotal, &s.RttMs, &s.RecordedAt); err != nil {
			log.Printf("snapshots scan: %v", err); continue
		}
		h.emit("snapshot", s)
		if s.RecordedAt.After(latest) { latest = s.RecordedAt }
	}
	return latest
}

func pushHeartbeats(ctx context.Context, db *sql.DB, h *hub, after time.Time) time.Time {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, rtt_ms, success, recorded_at
		 FROM heartbeats WHERE recorded_at > $1 ORDER BY recorded_at`, after)
	if err != nil { log.Printf("heartbeats query: %v", err); return after }
	defer rows.Close()
	latest := after
	for rows.Next() {
		var hb heartbeat
		if err := rows.Scan(&hb.ID, &hb.SessionID, &hb.RttMs,
			&hb.Success, &hb.RecordedAt); err != nil {
			log.Printf("heartbeats scan: %v", err); continue
		}
		h.emit("heartbeat", hb)
		if hb.RecordedAt.After(latest) { latest = hb.RecordedAt }
	}
	return latest
}

func pushTxLogs(ctx context.Context, db *sql.DB, h *hub, after time.Time) time.Time {
	rows, err := db.QueryContext(ctx,
		`SELECT id, session_id, event, status, detail, created_at
		 FROM transaction_log WHERE created_at > $1 ORDER BY created_at`, after)
	if err != nil { log.Printf("txlog query: %v", err); return after }
	defer rows.Close()
	latest := after
	for rows.Next() {
		var t txLog
		if err := rows.Scan(&t.ID, &t.SessionID, &t.Event,
			&t.Status, &t.Detail, &t.CreatedAt); err != nil {
			log.Printf("txlog scan: %v", err); continue
		}
		h.emit("txlog", t)
		if t.CreatedAt.After(latest) { latest = t.CreatedAt }
	}
	return latest
}

type historyResponse struct {
	Snapshots  []snapshot  `json:"snapshots"`
	Heartbeats []heartbeat `json:"heartbeats"`
	TxLogs     []txLog     `json:"tx_logs"`
}

func historyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := r.URL.Query().Get("session_id") // UUID string
		if sid == "" {
			http.Error(w, "missing session_id", http.StatusBadRequest)
			return
		}
		var resp historyResponse

		snapRows, err := db.QueryContext(r.Context(),
			`SELECT id, session_id, pub_ip, packets_sent, packets_recv,
			        dropped_packet, bytes_total, rtt_ms, recorded_at
			 FROM session_snapshots WHERE session_id = $1
			 ORDER BY recorded_at DESC LIMIT 50`, sid)
		if err == nil {
			defer snapRows.Close()
			for snapRows.Next() {
				var s snapshot
				if err := snapRows.Scan(&s.ID, &s.SessionID, &s.PubIP, &s.PacketsSent,
					&s.PacketsRecv, &s.DroppedPacket, &s.BytesTotal, &s.RttMs, &s.RecordedAt); err == nil {
					resp.Snapshots = append(resp.Snapshots, s)
				}
			}
		}

		hbRows, err := db.QueryContext(r.Context(),
			`SELECT id, session_id, rtt_ms, success, recorded_at
			 FROM heartbeats WHERE session_id = $1
			 ORDER BY recorded_at DESC LIMIT 50`, sid)
		if err == nil {
			defer hbRows.Close()
			for hbRows.Next() {
				var hb heartbeat
				if err := hbRows.Scan(&hb.ID, &hb.SessionID, &hb.RttMs,
					&hb.Success, &hb.RecordedAt); err == nil {
					resp.Heartbeats = append(resp.Heartbeats, hb)
				}
			}
		}

		txRows, err := db.QueryContext(r.Context(),
			`SELECT id, session_id, event, status, detail, created_at
			 FROM transaction_log WHERE session_id = $1
			 ORDER BY created_at DESC LIMIT 50`, sid)
		if err == nil {
			defer txRows.Close()
			for txRows.Next() {
				var t txLog
				if err := txRows.Scan(&t.ID, &t.SessionID, &t.Event,
					&t.Status, &t.Detail, &t.CreatedAt); err == nil {
					resp.TxLogs = append(resp.TxLogs, t)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func sseHandler(h *hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")

		ch := make(sseClient, 16)
		h.register <- ch
		defer func() { h.unregister <- ch }()

		for {
			select {
			case <-r.Context().Done():
				return
			case frame, ok := <-ch:
				if !ok { return }
				_, _ = w.Write(frame)
				flusher.Flush()
			}
		}
	}
}

func healthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil {
			http.Error(w, "db unreachable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func main() {
	cfg := cfgFromEnv()
	ctx := context.Background()

	db, err := sql.Open("postgres", cfg.DSN)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(3)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("db ping: %v", err)
	}
	log.Printf("db connected: %s", cfg.DSN)

	h := newHub()
	go h.run()
	go pollLoop(ctx, db, h, cfg.PollInterval)

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./static")))
	mux.HandleFunc("/events", sseHandler(h))
	mux.HandleFunc("/health", healthHandler(db))
	mux.HandleFunc("/history", historyHandler(db))

	log.Printf("listening on %s  poll=%s", cfg.ListenAddr, cfg.PollInterval)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}
