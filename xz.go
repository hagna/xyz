package xyz

import (
	"bufio"
	"container/list"
	"crypto/tls"
	"github.com/hashicorp/yamux"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
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
	relaydialtimeout                  = 5 * time.Second        /* time to wait for TLS to establish */
	relayidletimeout                  = 100 * time.Second      /* idle timeout for the local to relay connection */
	idletimeout         time.Duration = 800 * time.Millisecond /* time to wait for client to say something*/
	heartbeatinterval                 = 2 * time.Minute        /* time between beats */
	pruneclientinterval time.Duration = 1 * time.Minute        /* idle timeout for the local to relay connection */
)

// Use this to identify authentic clients
type authInfo struct {
	isX  bool
	name string
}

// For holding Y's state
type Relay struct {
	Xclients map[string]*Xclient /* the connected clients live here */
	Zclients map[string]*Zclient /* connected Z clients */
	listener net.Listener        /* the main port where it listens */
	sync.Mutex
}

// Each client gets one
type client struct {
	ctl      net.Conn       /* the control connection */
	pool     *list.List     /* all the connections TODO make it a list of *net.Conn */
	session  *yamux.Session /* use this to create new streams */
	authinfo *authInfo
	sync.Mutex
}

// Each client gets one
type Xclient struct {
	client
}

type Zclient struct {
	client
	connpool chan net.Conn /* for receiving conns */
}

// For holding X's state
type X struct {
	relayclients map[string]*relayclient /* the connected clients live here */
	sync.Mutex                           /* protect map from multiple writes */
}

// For holding Z's state
type Z struct {
	relayclients map[string]*relayclient /* the connected clients live here */
	sync.Mutex                           /* protect map from multiple writes */
}

// Each client gets one
type relayclient struct {
	token    []byte              /* identifier from the server */
	ctl      net.Conn            /* the control connection */
	connpool map[string]net.Conn /* connections stored by address */
	session  *yamux.Session      /* use this to create new streams */
}

// For starting X, which establishes a control connection to Y and then proxies each new connection from localendpoint through to Y and on to Z named name.
func StartXtls(config *tls.Config, localendpoint, relayendpoint, name string) (*X, error) {
	return startX(config, "", localendpoint, relayendpoint, name)
}

// For starting X, which establishes a control connection to Y and then proxies each new connection from localendpoint through to Y and on to Z named name. Send and an authentication message to Y with the output of running authscript.
func StartXauth(config *tls.Config, authscript, localendpoint, relayendpoint, name string) (*X, error) {
	return startX(config, authscript, localendpoint, relayendpoint, name)
}

func startX(config *tls.Config, authscript, localendpoint, relayendpoint, name string) (*X, error) {
	res := new(X)
	controlConnector := relayReconnector(config.Clone(), authscript, relayendpoint)
	ln, err := net.Listen("tcp", localendpoint)
	if err != nil {
		log.Printf("Error listening for local connection: %s", err)
		return nil, err
	}
	//log.Println("waiting for client connection")
	go func(endpoint string, ln net.Listener, controlConnector <-chan *relayclient, config *tls.Config, name string) {
		for {
			localconn, err := ln.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %s", err)
			}
			relayController := <-controlConnector
			handleLocalClient(endpoint, localconn, relayController, config, name)
		}
	}(relayendpoint, ln, controlConnector, config, name)

	return res, nil
}

// Return a list of Z's connected to the relayendpoint (Y). The relayendpoint would look like host:port.
func Xwho(config *tls.Config, authscript, relayendpoint string) ([]string, error) {
	controlConnector := relayReconnector(config.Clone(), authscript, relayendpoint)
	rc := <-controlConnector

	conn, err := dialRelay(relayendpoint, config)
	if err != nil {
		log.Printf("Error dialing relay: %s", err)
		return nil, err
	}
	defer conn.Close()
	_, err = send(conn, []byte(rc.token))
	if err != nil {
		log.Printf("Could not send token for WHO command: %s", err)
		return nil, err
	}
	_, err = send(conn, []byte("WHO"))
	if err != nil {
		log.Printf("Could not send WHO command: %s", err)
		return nil, err
	}
	res, err := recv(conn)
	if err != nil {
		log.Printf("Could not receive WHO list: %s", err)
		return nil, err
	}
	s := strings.Split(string(res), "\n")
	return s, nil
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
func dialRelay(endpoint string, config *tls.Config) (net.Conn, error) {
	config.ServerName = extractServername(endpoint)
	if config.ServerName == "" {
		log.Printf("Missing host part of host:port in \"%s\" something will break.", endpoint)
	}
	log.Printf("Dialing %s", endpoint)
	defer log.Printf("Done dialing %s", endpoint)
	dialer := &net.Dialer{Timeout: relaydialtimeout}
	return tls.DialWithDialer(dialer, "tcp", endpoint, config.Clone())
	//return tls.Dial("tcp", endpoint, config.Clone())
}

// for reconnecting the yamux connection, also known as the control channel, to the relay
func relayReconnector(config *tls.Config, authscript, endpoint string) <-chan *relayclient {
	rcChan := make(chan *relayclient)
	go func(config *tls.Config, endpoint string) {

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
		relayclient, err := makeControlConnection(config, authscript, endpoint)
		for {
			if err != nil || relayclient.session.IsClosed() {
				delay = math.Min(delay*factor, maxDelay)
				delay = mathrand.NormFloat64()*delay*jitter + delay
				backofftime := (time.Duration(int64(delay*float64(time.Second))) / time.Second) * time.Second
				if err != nil {
					log.Printf("Error %s. Trying again in %v", err, backofftime)
				} else {
					log.Printf("Session closed. Trying again in %v", backofftime)
				}
				time.Sleep(backofftime)
				goto CONNECT
				/* easier to follow than

				relayclient, err := connectrelayclient(config, endpoint)
				if err != nil {
					continue
				}
				*/
			}
			delay = initialDelay
			rcChan <- relayclient
			time.Sleep(200 * time.Millisecond)

		}

	}(config, endpoint)

	return rcChan
}

// A larger buffer size might be better
func proxyConn(rConn net.Conn, conn net.Conn) {

	timeout := relayidletimeout

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
func send(stream net.Conn, token []byte) (int, error) {
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
func recv(stream net.Conn) ([]byte, error) {
	connio := bufio.NewReader(io.LimitReader(stream, MAXMSGLENGTH))
	dat, err := connio.ReadBytes(byte(')'))
	if err != nil {
		return nil, err
	}
	return dat[1 : len(dat)-1], err
}

// timing out recv
func recvWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	message, err := recv(conn)
	conn.SetDeadline(time.Time{})
	return message, err
}

// X is a server and a client; this is the server side. Change here if you want to use sockets instead of tcp
func handleLocalClient(endpoint string, conn net.Conn, rc *relayclient, config *tls.Config, name string) {
	relayconn, err := dialRelay(endpoint, config)
	if err != nil {
		log.Printf("Error dialing relay: %s", err)
		conn.Close()
		return
	}
	_, err = send(relayconn, rc.token)
	if err != nil {
		log.Printf("Error SendingToken: %s", err)
		conn.Close()
		relayconn.Close()
		return
	}

	_, err = send(relayconn, []byte(name))
	if err != nil {
		log.Printf("Error sending name: %s", err)
		conn.Close()
		relayconn.Close()
		return
	}
	go proxyConn(conn, relayconn)

}

// For sending the token request from X to Y
func makeControlConnection(config *tls.Config, authscript, endpoint string) (*relayclient, error) {
	mathrand.Seed(time.Now().Unix())
	conn, err := dialRelay(endpoint, config.Clone())
	if err != nil {
		return nil, err
	}
	_, err = send(conn, []byte("TOK?"))
	if err != nil {
		log.Printf("Error writing token request: %s", err)
		conn.Close()
		return nil, err
	}
	if authscript != "" {
		log.Printf("running authscript %s", authscript)
		cmd := exec.Command(authscript)
		out, err := cmd.Output()
		if err != nil {
			log.Printf("Could not run authscript \"%s\": %s", authscript, err)
		} else {
			log.Printf("Sending output of script: \"%s\"", string(out))
			_, err = send(conn, out)
			if err != nil {
				log.Printf("Could not send output of authscript to conn: %s", err)
			}
		}
	}
	relayclient := new(relayclient)
	relayclient.token, err = recvWithTimeout(conn, idletimeout*4)
	if err != nil {
		conn.Close()
		log.Printf("Error reading token: %s", err)
		return nil, err
	}
	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = heartbeatinterval
	conf.EnableKeepAlive = true
	session, err := yamux.Client(conn, conf)
	if err != nil {
		log.Printf("Error setting up yamux client: %s", err)
		conn.Close()
		return nil, err
	}
	stream, err := session.Open()
	if err != nil {
		session.Close()
		conn.Close()
		log.Println("Error opening session: %s", err)
		return nil, err
	}
	relayclient.ctl = stream
	relayclient.session = session

	log.Printf("Connecion established %s %s", relayclient.ctl.LocalAddr(), relayclient.ctl.RemoteAddr())
	/*
		x.Lock()
		x.relayclients[string(relayclient.token)] = relayclient
		x.Unlock()
	*/
	return relayclient, nil
}

func StartZ(config *tls.Config, authscript, localendpoint, relayendpoint string) (*Z, error) {
	log.Printf("StartZ authscript = \"%v\"", authscript)
	controlConnector := relayReconnector(config.Clone(), authscript, relayendpoint)
	go func() {
		for {
			relay := <-controlConnector
			message, err := recv(relay.ctl)
			if err != nil {
				log.Printf("Error receiving control message: %s", err)
				continue
			}
			if string(message) == "CONNECT" {
				conn, err := dialRelay(relayendpoint, config.Clone())
				if err != nil {
					log.Printf("Error dialing relay: %s", err)
					continue
				}
				_, err = send(conn, relay.token)
				server, err := net.Dial("tcp", localendpoint)
				if err != nil {
					log.Printf("Error dialing local server: %s", err)
					continue
				}
				proxyConn(conn, server)
			}
		}
	}()
	return nil, nil
}
