package tracker

import (
	"time"

	"dpi-engine/types"
)

// ConnectionTracker maintains a per-worker map of connections keyed by FiveTuple.
// It is NOT thread-safe — each worker goroutine owns its own tracker.
type ConnectionTracker struct {
	connections map[types.FiveTuple]*types.Connection
}

// NewConnectionTracker creates a new ConnectionTracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[types.FiveTuple]*types.Connection),
	}
}

// GetOrCreate looks up a connection by tuple, trying both forward and reverse.
// If not found, creates a new connection. Returns the connection and whether
// the packet is in the reverse direction.
func (ct *ConnectionTracker) GetOrCreate(tuple types.FiveTuple, now time.Time) (*types.Connection, bool) {
	// Try forward lookup
	if conn, ok := ct.connections[tuple]; ok {
		conn.LastSeen = now
		return conn, false
	}

	// Try reverse lookup
	rev := tuple.Reverse()
	if conn, ok := ct.connections[rev]; ok {
		conn.LastSeen = now
		return conn, true
	}

	// Evict oldest if at capacity
	if len(ct.connections) >= types.MaxConnectionsPerWorker {
		ct.evictOldest()
	}

	// Create new connection
	conn := &types.Connection{
		Tuple:     tuple,
		State:     types.StateNew,
		AppType:   types.AppUnknown,
		FirstSeen: now,
		LastSeen:  now,
	}
	ct.connections[tuple] = conn
	return conn, false
}

// UpdateTCPState updates the TCP state machine based on packet flags.
func UpdateTCPState(conn *types.Connection, flags uint8) {
	hasSYN := flags&types.TCPFlagSYN != 0
	hasACK := flags&types.TCPFlagACK != 0
	hasRST := flags&types.TCPFlagRST != 0
	hasFIN := flags&types.TCPFlagFIN != 0

	if hasRST {
		conn.State = types.StateClosed
		return
	}

	if hasSYN && !hasACK {
		conn.SynSeen = true
		return
	}

	if hasSYN && hasACK {
		conn.SynAckSeen = true
		return
	}

	if hasACK && conn.SynAckSeen && conn.State == types.StateNew {
		conn.State = types.StateEstablished
	}

	if hasFIN {
		if conn.FinSeen {
			// FIN+ACK after FinSeen
			conn.State = types.StateClosed
		} else {
			conn.FinSeen = true
		}
	}

	if hasFIN && hasACK && conn.FinSeen {
		conn.State = types.StateClosed
	}
}

// ClassifyConnection sets the app type and SNI on a connection and marks it classified.
func ClassifyConnection(conn *types.Connection, appType types.AppType, sni string) {
	conn.AppType = appType
	conn.SNI = sni
	if conn.State != types.StateBlocked {
		conn.State = types.StateClassified
	}
}

// CleanupExpired removes connections that are closed or have been idle longer
// than the connection timeout.
func (ct *ConnectionTracker) CleanupExpired(now time.Time) int {
	removed := 0
	for tuple, conn := range ct.connections {
		if conn.State == types.StateClosed || now.Sub(conn.LastSeen) > types.ConnectionTimeout {
			delete(ct.connections, tuple)
			removed++
		}
	}
	return removed
}

// ActiveCount returns the number of active connections.
func (ct *ConnectionTracker) ActiveCount() int {
	return len(ct.connections)
}

// evictOldest removes the connection with the oldest LastSeen timestamp.
func (ct *ConnectionTracker) evictOldest() {
	var oldestTuple types.FiveTuple
	var oldestTime time.Time
	first := true

	for tuple, conn := range ct.connections {
		if first || conn.LastSeen.Before(oldestTime) {
			oldestTuple = tuple
			oldestTime = conn.LastSeen
			first = false
		}
	}

	if !first {
		delete(ct.connections, oldestTuple)
	}
}
