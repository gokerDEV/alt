package dcnet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

const MaxActiveChannels = 16

// Session manages a single PeerConnection and enforces the 16-channel budget.
type Session struct {
	pc        *webrtc.PeerConnection
	ctx       context.Context
	cancel    context.CancelFunc
	transport *http.Transport

	chanSeq  atomic.Uint64
	sem      chan struct{} // Limits active channels to 16
	acceptCh chan net.Conn

	mu     sync.Mutex
	active map[*Conn]struct{}
	closed bool
}

// NewSession initializes a Session over a PeerConnection that was created with
// SettingEngine.DetachDataChannels().
func NewSession(parentCtx context.Context, pc *webrtc.PeerConnection) *Session {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &Session{
		pc:       pc,
		ctx:      ctx,
		cancel:   cancel,
		sem:      make(chan struct{}, MaxActiveChannels),
		acceptCh: make(chan net.Conn, MaxActiveChannels),
		active:   make(map[*Conn]struct{}),
	}

	s.transport = &http.Transport{
		DialContext:           s.DialContext,
		MaxIdleConns:          MaxActiveChannels,
		MaxIdleConnsPerHost:   MaxActiveChannels,
		MaxConnsPerHost:       MaxActiveChannels,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	pc.OnDataChannel(s.handleIncomingDataChannel)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateDisconnected {
			_ = s.Close()
		}
	})

	return s
}

// Transport returns the session-scoped http.Transport for the visitor ReverseProxy.
func (s *Session) Transport() *http.Transport {
	return s.transport
}

// DialContext opens a reliable, ordered DataChannel per upstream HTTP/1.1 connection.
func (s *Session) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	select {
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	select {
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case s.sem <- struct{}{}:
	}

	ordered := true
	id := s.chanSeq.Add(1)
	label := fmt.Sprintf("alt-http-v1-%d", id)

	dc, err := s.pc.CreateDataChannel(label, &webrtc.DataChannelInit{
		Ordered: &ordered,
	})
	if err != nil {
		<-s.sem
		return nil, err
	}

	openCh := make(chan struct{})
	dc.OnOpen(func() {
		close(openCh)
	})

	select {
	case <-openCh:
	case <-ctx.Done():
		_ = dc.Close()
		<-s.sem
		return nil, ctx.Err()
	case <-s.ctx.Done():
		_ = dc.Close()
		<-s.sem
		return nil, ErrSessionClosed
	}

	conn, err := s.registerConn(dc)
	if err != nil {
		_ = dc.Close()
		<-s.sem
		return nil, err
	}

	return conn, nil
}

func (s *Session) handleIncomingDataChannel(dc *webrtc.DataChannel) {
	select {
	case s.sem <- struct{}{}:
	default:
		// Reject immediately if publisher already has 16 active channels
		_ = dc.Close()
		return
	}

	dc.OnOpen(func() {
		conn, err := s.registerConn(dc)
		if err != nil {
			_ = dc.Close()
			<-s.sem
			return
		}

		select {
		case s.acceptCh <- conn:
		case <-s.ctx.Done():
			_ = conn.Close()
		}
	})
}

func (s *Session) registerConn(dc *webrtc.DataChannel) (*Conn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}

	var conn *Conn
	var err error
	conn, err = Wrap(s.ctx, dc, func() {
		s.mu.Lock()
		delete(s.active, conn)
		s.mu.Unlock()
		<-s.sem
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	s.active[conn] = struct{}{}
	s.mu.Unlock()
	return conn, nil
}

// Accept implements net.Listener for the Publisher's http.Server.
func (s *Session) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-s.acceptCh:
		if !ok {
			return nil, ErrSessionClosed
		}
		return conn, nil
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// Addr implements net.Listener.
func (s *Session) Addr() net.Addr {
	return dcAddr{network: "webrtc-dc", label: "publisher-listener"}
}

// Close stops new dials, closes idle HTTP connections, and terminates all active channels.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()

	activeConns := make([]*Conn, 0, len(s.active))
	for c := range s.active {
		activeConns = append(activeConns, c)
	}
	s.mu.Unlock()

	s.transport.CloseIdleConnections()
	for _, c := range activeConns {
		_ = c.Close()
	}

	return s.pc.Close()
}
