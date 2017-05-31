package xyz

import (
	"bufio"
	"io"
	"log"
	"net"
	"time"
)

const (
	PROXYCHUNK    = 1024
	MESSAGELENGTH = 4
	MAXMSGLENGTH  = 2048
	TOKENLENGTH   = 1024
	NAMELENGTH    = 10
)

var (
	Relayidletimeout = 100 * time.Second /* idle timeout for the local to relay connection */
)

// A larger buffer size might be better
func ProxyConn(rConn net.Conn, conn net.Conn) {

	timeout := Relayidletimeout

	go func() {
		defer rConn.Close()
		defer conn.Close()
		for {
			buf := make([]byte, PROXYCHUNK)
			conn.SetDeadline(time.Now().Add(timeout))
			n, e := conn.Read(buf)
			var e1 error
			if n > 0 {
				_, e1 = rConn.Write(buf[:n])
			}
			if e != nil {
				log.Printf("Exiting on read %p: %s", rConn, e)
				break
			}
			if e1 != nil {
				log.Printf("Exiting on write %p: %s", conn, e1)
				log.Println(e1)
				break
			}
		}
	}()

	go func() {
		defer rConn.Close()
		defer conn.Close()
		for {
			buf := make([]byte, PROXYCHUNK)
			rConn.SetDeadline(time.Now().Add(timeout))
			n, e := rConn.Read(buf)
			var e1 error
			if n > 0 {
				_, e1 = conn.Write(buf[:n])
			}
			if e != nil {
				log.Printf("Exiting on read %p: %s", rConn, e)
				break
			}
			if e1 != nil {
				log.Printf("Exiting on write %p: %s", conn, e1)
				break
			}
		}
	}()

}

// messages look like something like this (ll+aFFesdfbASDFASDsdf112323/sdfasd)
func Send(stream net.Conn, token []byte) (int, error) {
	message := []byte("(")
	message = append(message, token...)
	message = append(message, []byte(")")...)
	if len(message) > MAXMSGLENGTH {
		orig := message
		message = message[:MAXMSGLENGTH-1]
		message = append(message, []byte(")")...)
		log.Printf("WARNING truncated send [%d]%v...%v to [%d]%v...%v", len(orig), orig[:10], orig[len(orig)-10:len(orig)], len(message), message[:10], message[len(message)-10:len(message)])
	}
	n, err := stream.Write(message)
	if err != nil {
		log.Printf("writing token [%d]%s", n, string(message[:n]))
	}
	return n, err
}

// oh wouldn't the devsec people -- ok, they'll never be happy -- but I'm using parenthesis delimited base64 for network messages.
func Recv(stream net.Conn) ([]byte, error) {
	connio := bufio.NewReader(io.LimitReader(stream, MAXMSGLENGTH))
	dat, err := connio.ReadBytes(byte(')'))
	if err != nil {
		return nil, err
	}
	return dat[1 : len(dat)-1], err
}

// timing out recv
func RecvWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	message, err := Recv(conn)
	conn.SetDeadline(time.Time{})
	return message, err
}
