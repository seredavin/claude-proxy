package gateway

import (
	"context"
	"net"
	"time"
)

// deadlineConn обновляет дедлайн перед каждой операцией, превращая его из
// ограничения на всю передачу в ограничение на паузу между байтами.
//
// Так работал nginx: proxy_read_timeout и proxy_send_timeout отсчитываются
// заново после каждого успешного обмена. Без этого длинный SSE-ответ пришлось
// бы либо обрывать по общему сроку, либо не ограничивать вовсе — а второе
// означает, что молча зависшее соединение (half-open TCP, разрыв маршрута без
// RST) держится до перезапуска процесса.
type deadlineConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		if err := c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

// dialWithDeadlines возвращает DialContext, оборачивающий соединение в
// deadlineConn.
func dialWithDeadlines(dialer *net.Dialer, read, write time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &deadlineConn{Conn: conn, readTimeout: read, writeTimeout: write}, nil
	}
}
