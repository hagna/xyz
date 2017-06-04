package xyz

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/hashicorp/yamux"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"runtime"
	"strings"
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
	verboselevel     = 0
)

// the verboselevel function
func debug(lvl int, m string) {
	if verboselevel > lvl {
		pc, fn, line, _ := runtime.Caller(1)
		fmt.Printf("%s %s:%d %s", runtime.FuncForPC(pc).Name(), fn, line, m)
	}
}

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
				//log.Printf("Exiting on read %p: %s", rConn, e)
				break
			}
			if e1 != nil {
				//log.Printf("Exiting on write %p: %s", conn, e1)
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
				//log.Printf("Exiting on read %p: %s", rConn, e)
				break
			}
			if e1 != nil {
				//log.Printf("Exiting on write %p: %s", conn, e1)
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
		log.Printf("truncated send [%d]%v...%v to [%d]%v...%v and this will likely break something down the line", len(orig), orig[:10], orig[len(orig)-10:len(orig)], len(message), message[:10], message[len(message)-10:len(message)])
	}
	n, err := stream.Write(message)
	if err != nil {
		//log.Printf("writing token [%d]%s", n, string(message[:n]))
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

// Each client gets one
type RelayClient struct {
	token    []byte              /* identifier from the server */
	ctl      net.Conn            /* the control connection */
	connpool map[string]net.Conn /* connections stored by address */
	session  *yamux.Session      /* use this to create new streams */
}

// take the server out of server:83984
func extractServername(ep string) string {
	res := strings.Split(ep, ":")
	if len(res) == 2 {
		return res[0]
	} else {
		log.Printf("Could not split \"%s\" on the \":\" so returning \"\" which will break something surely.", ep)
	}
	return ""
}

// Dial the relay; setup the SAN
func DialRelay(endpoint string, config *tls.Config) (net.Conn, error) {
	config.ServerName = extractServername(endpoint)
	if config.ServerName == "" {
		log.Printf("Missing host part of host:port in \"%s\" something will break.", endpoint)
	}
	return tls.Dial("tcp", endpoint, config.Clone())
}

// A client that backs off when it fails to connect again
func ReconnectingClient(config *tls.Config, endpoint string, rcChan chan *RelayClient, clientFn func(*tls.Config, string) (*RelayClient, error)) {

	var (
		maxDelay     = 120.00
		initialDelay = 1.0
		factor       = 2.7182818284590451 // e
		jitter       = 0.11962656472      // molar Planck constant times c, joule meter/mole
		delay        = initialDelay
		//lastconnect  time.Time
		//shortconnect = 10 * time.Second
	)
CONNECT:
	relayclient, err := clientFn(config, endpoint)
	for {
		if err != nil || relayclient.session.IsClosed() {
			delay = math.Min(delay*factor, maxDelay)
			delay = mathrand.NormFloat64()*delay*jitter + delay
			backofftime := (time.Duration(int64(delay*float64(time.Second))) / time.Second) * time.Second
			log.Printf("Relay control closed trying again in %v", backofftime)
			time.Sleep(backofftime)
			goto CONNECT
			/* easier to follow than

			relayclient, err := connectRelayClient(config, endpoint)
			if err != nil {
				continue
			}
			*/
		}
		delay = initialDelay
		rcChan <- relayclient
		time.Sleep(200 * time.Millisecond)

	}
}
