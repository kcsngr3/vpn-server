package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type DbHandler struct {
	db       *sql.DB
	serverId string
	region   string
}

func initDb(connStr string, serverId string, region string) (*DbHandler, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	fmt.Println("Conncection ok")
	return &DbHandler{db: db, serverId: serverId, region: region}, nil
}
func (h *DbHandler) TxInitServer(serverID, ip, region string) error {
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}

	// lock the row to prevent race condition
	var exists bool
	err = tx.QueryRow(`
    SELECT EXISTS(SELECT 1 FROM servers WHERE server_id = $1)`,
		serverID,
	).Scan(&exists)
	if err != nil {
		tx.Rollback()
		return err
	}

	if exists {
		tx.Rollback()
		fmt.Printf("Server %s already registered — skipping\n", serverID)
		return nil
	}

	_, err = tx.Exec(`
		INSERT INTO servers(server_id, ip, region)
		VALUES($1, $2, $3)`,
		serverID, ip, region,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	// _, err = tx.Exec(`
	// 	INSERT INTO transaction_log(session_id, event, status)
	// 	VALUES(NULL, 'SERVER_INIT', 'COMMITTED')`,
	// )
	// if err != nil {
	// 	tx.Rollback()
	// 	return err
	// }

	return tx.Commit()
}

// auth
func (h *DbHandler) TxCreateSession(
	sessID string,
	vpnIP string,
	sessionKey string,
) (string, error) {
	tx, err := h.db.Begin()
	if err != nil {
		return "", err
	}

	var id string
	err = tx.QueryRow(`
		INSERT INTO sessions(session_id, server_id, vpn_ip, session_key)
		VALUES($1, $2, $3, $4)
		RETURNING id`,
		sessID, h.serverId, vpnIP, sessionKey,
	).Scan(&id)
	if err != nil {
		tx.Rollback()
		return "", err
	}

	_, err = tx.Exec(`
		INSERT INTO transaction_log(session_id, event, status)
		VALUES($1, 'CONNECT', 'COMMITTED')`, id,
	)
	if err != nil {
		tx.Rollback()
		return "", err
	}

	return id, tx.Commit()
}

func (h *DbHandler) InsertHb(dbsessionID string, rttMs float64, success bool) error {
	_, err := h.db.Exec(`
		INSERT INTO heartbeats(session_id, rtt_ms, success)
		VALUES($1, $2, $3)`,
		dbsessionID, rttMs, success,
	)
	return err
}

// localLog
func (h *DbHandler) TxInsertSessionSnapshot(
	dbsessionID string,
	pubIP string,
	pktSent int64,
	pktRecv int64,
	pktDropped int64,
	bytesTotal int64,
	rttMs float64,
) error {
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO session_snapshots(session_id, pub_ip, packets_sent, packets_recv, dropped_packet, bytes_total, rtt_ms)
		VALUES($1, $2, $3, $4, $5, $6, $7)`,
		dbsessionID, pubIP, pktSent, pktRecv, pktDropped, bytesTotal, rttMs,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO transaction_log(session_id, event, status)
		VALUES($1, 'SNAPSHOT', 'COMMITTED')`, dbsessionID,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// watchdog
func (h *DbHandler) TxDisconnectByHbFail(dbSessinID string, rttMs float64) error {
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO heartbeats(session_id, rtt_ms, success)
		VALUES($1, $2, false)`,
		dbSessinID, rttMs,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec(`
		UPDATE sessions SET disconnected_at = now()
		WHERE id = $1`, dbSessinID,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO transaction_log(session_id, event, status)
		VALUES($1, 'DISCONNECT_HB_FAIL', 'COMMITTED')`, dbSessinID,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (h *DbHandler) Close() {
	h.db.Close()
}
