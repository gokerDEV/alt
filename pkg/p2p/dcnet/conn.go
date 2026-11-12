package dcnet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v4"
)

const (
	MaxChunkSize          = 16 * 1024  // 16 KiB max write chunk
	MaxBufferedAmount     = 256 * 1024 // 256 KiB send queue ceiling
	BufferedAmountLowMark = 128 * 1024 // 128 KiB wake-up threshold
)

var (
	ErrChannelClosed = errors.New("dcnet: datachannel closed")
	ErrSessionClosed = errors.New("dcnet: session closed")
	ErrMaxChannels   = errors.New("dcnet: active channel limit reached (max 16)")
)

type dcAddr struct {
	network string
	label   string
}

func (a dcAddr) Network() string { return a.network }
func (a dcAddr) String() string  { return a.label }

// Conn implements net.Conn over a detached Pion WebRTC DataChannel.
type Conn struct {
	dc      *webrtc.DataChannel
	raw     datachannel.ReadWriteCloserDeadliner
	local   net.Addr
	remote  net.Addr
	onClose func()

	writeMu sync.Mutex // Serializes net.Conn.Write per channel
	readMu  sync.Mutex // Protects readBuf for small Read(p) calls
	readBuf bytes.Buffer
	msgBuf  []byte

	notifyCh   chan struct{}
	closeOnce  sync.Once
	closedCh   chan struct{}
	sessionCtx context.Context

	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

// Wrap detached a configured DataChannel (with DetachWithDeadline enabled on SettingEngine)
// and sets up the backpressure callbacks once upon initialization.
func Wrap(sessionCtx context.Context, dc *webrtc.DataChannel, onClose func()) (*Conn, error) {
	raw, err := dc.DetachWithDeadline()
	if err != nil {
		return nil, err
	}

	c := &Conn{
		dc:         dc,
		raw:        raw,
		local:      dcAddr{network: "webrtc-dc", label: dc.Label()},
		remote:     dcAddr{network: "webrtc-dc", label: dc.Label()},
		onClose:    onClose,
		msgBuf:     make([]byte, 64*1024),
		notifyCh:   make(chan struct{}, 1),
		closedCh:   make(chan struct{}),
		sessionCtx: sessionCtx,
	}

	dc.SetBufferedAmountLowThreshold(BufferedAmountLowMark)
	dc.OnBufferedAmountLow(func() {
		c.signalWakeup()
	})
	dc.OnClose(func() {
		_ = c.Close()
	})

	return c, nil
}

func (c *Conn) signalWakeup() {
	select {
	case c.notifyCh <- struct{}{}:
	default:
	}
}

// Read reads from the internal buffer if residual bytes exist, otherwise pulls the next
// SCTP message from the underlying DataChannel. Empty messages are ignored (not treated as EOF).
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	for {
		select {
		case <-c.closedCh:
			return 0, io.EOF
		case <-c.sessionCtx.Done():
			return 0, ErrSessionClosed
		default:
		}

		n, _, err := c.raw.ReadDataChannel(c.msgBuf)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			// Empty SCTP message is not EOF per spec
			continue
		}

		copied := copy(p, c.msgBuf[:n])
		if copied < n {
			_, _ = c.readBuf.Write(c.msgBuf[copied:n])
		}
		return copied, nil
	}
}

// Write serializes writes, splits payload into <= 16 KiB chunks, and enforces
// BufferedAmount() + chunkLen <= 256 KiB using race-free double-check signaling.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalWritten := 0
	for len(p) > 0 {
		chunkLen := len(p)
		if chunkLen > MaxChunkSize {
			chunkLen = MaxChunkSize
		}
		chunk := p[:chunkLen]

		if err := c.waitForBufferSpace(uint64(chunkLen)); err != nil {
			return totalWritten, err
		}

		n, err := c.raw.Write(chunk)
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
		p = p[n:]
	}

	return totalWritten, nil
}

func (c *Conn) waitForBufferSpace(chunkLen uint64) error {
	for {
		select {
		case <-c.closedCh:
			return ErrChannelClosed
		case <-c.sessionCtx.Done():
			return ErrSessionClosed
		default:
		}

		if c.dc.BufferedAmount()+chunkLen <= MaxBufferedAmount {
			return nil
		}

		// Drain stale notification before registering wait state
		select {
		case <-c.notifyCh:
		default:
		}

		// Double-check condition after arming wait state to prevent lost wake-ups
		if c.dc.BufferedAmount()+chunkLen <= MaxBufferedAmount {
			return nil
		}

		var timer *time.Timer
		var timeoutCh <-chan time.Time

		c.deadlineMu.Lock()
		wd := c.writeDeadline
		c.deadlineMu.Unlock()

		if !wd.IsZero() {
			d := time.Until(wd)
			if d <= 0 {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeoutCh = timer.C
		}

		select {
		case <-c.notifyCh:
			if timer != nil {
				timer.Stop()
			}
		case <-c.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return ErrChannelClosed
		case <-c.sessionCtx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ErrSessionClosed
		case <-timeoutCh:
			return os.ErrDeadlineExceeded
		}
	}
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closedCh)
		c.signalWakeup()
		err = c.raw.Close()
		_ = c.dc.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.signalWakeup()
	return c.raw.SetWriteDeadline(t)
}

