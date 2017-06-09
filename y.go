package xyz

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/yamux"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Start the relay on each endpoint of the form host:port listed.
func StartY(config *tls.Config, authscript string, noverify bool, endpoints []string) (*Relay, error) {
	relay := new(Relay)
	relay.Xclients = make(map[string]*Xclient)
	relay.Zclients = make(map[string]*Zclient)
	go relay.pruneClients()
	for _, networkendpoint := range endpoints {
		ln, err := tls.Listen("tcp", networkendpoint, config)
		if err != nil {
			return nil, err
		}
		relay.listener = ln
		//log.Printf("listening on %s\n", ln.Addr().String())
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				log.Printf("connection %s", conn.RemoteAddr())
				if err != nil {
					log.Println("error on Accept:", err)
					continue
				}
				tconn, ok := conn.(*tls.Conn)
				if !ok {
					log.Println("Not a TLS connection")
					continue
				}
				go relay.HandleConn(authscript, noverify, tconn)
			}
		}(ln)
	}
	return relay, nil
}

// for removing the conn from the list
func (c *client) stopTrackingConn(conn net.Conn) error {
	c.Lock()
	var next *list.Element
	for e := c.pool.Front(); e != nil; e = next {
		next = e.Next()
		b, ok := e.Value.(net.Conn)
		if !ok {
			log.Printf("BUGBUG list did not contain net.Conn")
		}
		if b == conn {
			//log.Printf("Stop tracking %s to %s", b.LocalAddr().String(), b.RemoteAddr().String())
			c.pool.Remove(e)
		}
	}
	c.Unlock()
	return nil
}

// for destroying all the connections corresponding to one client
func (c *client) Close() error {
	var next *list.Element
	for e := c.pool.Front(); e != nil; e = next {
		next = e.Next()
		b, ok := e.Value.(net.Conn)
		if !ok {
			log.Printf("BUGBUG list did not contain net.Conn")
		}
		b.Close()
		c.pool.Remove(e)

	}
	if !c.session.IsClosed() {
		c.session.Close()
	}
	return nil
}

// List the clients by name
func (Y *Relay) whoList() []string {
	names := []string{}
	Y.Lock()
	for _, v := range Y.Zclients {
		names = append(names, v.authinfo.name)
	}
	Y.Unlock()
	return names
}

// clean up connections that have closed thanks to yamux KeepAlive
func (Y *Relay) pruneClients() error {
	for {

		Y.Lock()
		var deleteme []string
		for k, v := range Y.Xclients {
			v.Lock()
			if v.session.IsClosed() {
				//log.Printf("%s has closed so closing connections", v.authinfo.name)
				v.Close()
				deleteme = append(deleteme, k)
			}
			v.Unlock()
		}

		for _, v := range deleteme {
			delete(Y.Xclients, v)
		}
		deleteme = []string{}
		for k, v := range Y.Zclients {
			v.Lock()
			if v.session.IsClosed() {
				//log.Printf("%s has closed so closing connections", v.authinfo.name)
				v.Close()
				deleteme = append(deleteme, k)
			}
			v.Unlock()
		}
		for _, v := range deleteme {
			delete(Y.Zclients, v)
		}

		Y.Unlock()
		time.Sleep(pruneclientinterval)
	}
	return nil
}

// for cleaning up and closing down the relay
func (Y *Relay) Close() error {
	Y.pruneClients()
	Y.listener.Close()
	return nil
}

// conn is type X or Z and it has a name too. We can find out with certs first and then scripts.
// authscript returns X:realname if it's an X type of client
func (*Relay) Authenticate(authscript string, noverify bool, conn net.Conn) (*authInfo, error) {
	authinfo := new(authInfo)
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("Auth failed could not cast to TLS connection")
	}
	cs := tconn.ConnectionState()
	//log.Printf("\tPeerCertificates:")
	for _, v := range cs.PeerCertificates {
		authinfo.name = v.Subject.CommonName
		z := v.Subject.OrganizationalUnit
		ou := ""
		if len(z) >= 1 {
			ou = z[0]
		}
		//log.Printf("\t\t%d: %+v\n", i, v.Subject)
		if ou == "X" {
			authinfo.isX = true
			break
		}
	}
	//log.Printf("\tVerified chains:")
	/*for i, v := range cs.VerifiedChains {
		//log.Printf("\t\t%d: %+v\n", i, v)
	}
	*/
	verifycert := !noverify
	if cs.VerifiedChains == nil {
		if authscript != "" {
			//log.Println("trying to receive auth")
			cookie, err := recvWithTimeout(conn, idletimeout)
			if err != nil { // no auth cookie
				err2 := fmt.Errorf("Error receiving auth cookie: %s", err)
				if verifycert {
					return nil, err2
				} else {
					log.Printf("Letting connection continue despite: %s", err2)
				}
			} else {
				cmd := exec.Command(authscript)
				cmd.Env = os.Environ()
				cmd.Env = append(cmd.Env, "RemoteAddr="+conn.RemoteAddr().String())
				cmd.Env = append(cmd.Env, "LocalAddr="+conn.LocalAddr().String())
				stdin, err := cmd.StdinPipe()
				if err != nil {
					return nil, fmt.Errorf("Error writing to stdin of \"%s\": %s", authscript, err)
				}
				fmt.Fprintf(stdin, string(cookie))
				out, err := cmd.Output()
				if err != nil {
					return nil, fmt.Errorf("Error on exit \"%s\": %s", authscript, err)
				}
				name := string(out)
				name = strings.TrimSpace(name)
				conntype := "Z"
				if strings.Index(name, ":") != -1 {
					z := strings.Split(name, ":")
					if len(z) != 2 {
						return nil, fmt.Errorf("Auth failed: expected type:name in %v", name)
					}
					conntype, name = z[0], z[1]
					if conntype == "X" {
						authinfo.isX = true
					}
				}
				authinfo.name = name
			}
		} else {
			if verifycert {
				return nil, fmt.Errorf("Could not authorize certificate.")
			}
		}
	}
	if authinfo.name == "" {
		b, err := nRandomBytes64(NAMELENGTH)
		if err != nil {
			log.Printf("No random bytes for name :(")
		}
		authinfo.name = string(b)
	}
	return authinfo, nil
}

// Make the control (yamux) connection to X or Z and send the token response
func (server *Relay) makeControlConnection(authscript string, noverify bool, conn net.Conn) error {
	authinfo, err := server.Authenticate(authscript, noverify, conn)
	if err != nil {
		conn.Close()
		return err
	}
	token, err := nRandomBytes64(TOKENLENGTH)
	if err != nil {
		conn.Close()
		return err
	}
	_, err = send(conn, token)
	if err != nil {
		conn.Close()
		return err
	}
	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = heartbeatinterval

	session, err := yamux.Server(conn, conf)
	if err != nil {
		session.Close()
		conn.Close()
		return err
	}
	stream, err := session.Accept()
	if err != nil {
		log.Printf("error accepting stream: %s", err)
		stream.Close()
		session.Close()
		conn.Close()
		return err
	}
	//log.Println("accepted yamux stream")

	ttype := "Z"
	if authinfo.isX {
		ttype = "X"
		client := new(Xclient)
		client.ctl = stream
		client.authinfo = authinfo
		client.session = session
		client.pool = list.New()
		server.Lock()
		server.Xclients[string(token)] = client
		server.Unlock()
	} else {
		client := new(Zclient)
		client.connpool = make(chan net.Conn)
		client.ctl = stream
		client.authinfo = authinfo
		client.session = session
		client.pool = list.New()
		server.Lock()
		server.Zclients[string(token)] = client
		server.Unlock()
	}

	log.Printf("%s %s %s", ttype, conn.RemoteAddr(), conn.LocalAddr())
	return nil
}

// give us N bytes of base64
func nRandomBytes64(N uint32) ([]byte, error) {
	b := make([]byte, N)
	b64 := bytes.NewBuffer(make([]byte, N))
	_, err := rand.Reader.Read(b)
	if err != nil {
		return nil, err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, b64)
	b64.Reset()
	encoder.Write(b)
	encoder.Close()
	return b64.Bytes(), nil
}

// clients request tokens or send tokens. If using authscript they send a token request and an auth blob.
func (server *Relay) HandleConn(authscript string, noverify bool, conn *tls.Conn) {
	message, err := recvWithTimeout(conn, idletimeout)
	if err != nil {
		log.Printf("Error closing \"%v\": %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	switch string(message) {
	case "TOK?":
		err := server.makeControlConnection(authscript, noverify, conn)
		if err != nil {
			log.Printf("Could not make control connection: %v", err)
		}
	default:
		token := message
		if len(token) < TOKENLENGTH {
			log.Printf("Token too short: %v", token)
			conn.Close()
		}

		server.Lock()
		xclient, isX := server.Xclients[string(token)]
		server.Unlock()
		/*conntype := "X"
		if !isX {
			conntype = "Z"
		}*/
		if isX {
			b, err := recvWithTimeout(conn, idletimeout)
			name := string(b)
			if err != nil {
				log.Printf("Error receiving name from %s: %s", conn.RemoteAddr(), err)
			}
			if name == "WHO" {
				tosend := []byte{}
				for _, v := range server.whoList() {
					tosend = append(tosend, []byte(v+"\n")...)
				}

				_, err := send(conn, tosend)
				if err != nil {
					log.Printf("Could not send whoList(): %s", err)
				}
				conn.Close()
				return
			}
			server.Lock()
			if len(server.Zclients) == 0 {
				server.Unlock()
				m := "No Z to connect to\n"
				//log.Printf("sending %s", m)
				_, _ = conn.Write([]byte(m))
				conn.Close()
				return
			}
			server.Unlock()

			zclient := new(Zclient)
			server.Lock()
			for _, v := range server.Zclients {
				//log.Printf("Does zclient \"%s\" match \"%s\"", v.authinfo.name, name)
				zclient = v
				if v.authinfo.name == name {
					zclient = v
					break
				}
			}
			if len(server.Zclients) > 1 && zclient.authinfo.name != name {
				server.Unlock()
				log.Printf("Could not find Z client named \"%s\" in many Z clients: %+v", name, server.whoList())
				conn.Close()
				return
			}
			if zclient.authinfo.name != name {
				log.Printf("Y is connecting \"%s\" instead of \"%s\" because only \"%s\" exists", zclient.authinfo.name, name, zclient.authinfo.name)
			}

			server.Unlock()
			_, err = send(zclient.ctl, []byte("CONNECT"))
			if err != nil {
				log.Printf("Error sending connect message to Z: %s", err)
				conn.Close()
				return
			}
			zconn := <-zclient.connpool
			//log.Printf("Adding %p to Xpool", conn)
			xclient.Lock()
			xclient.pool.PushBack(conn)
			xclient.Unlock()

			log.Printf("Begin proxy X (%s) Y (%s) Z (%s)", conn.RemoteAddr(), conn.LocalAddr(), zconn.RemoteAddr())
			proxyConn(conn, zconn)
			//log.Printf("Proxy started between Z (%p) and X (%p)", zconn, conn)
			xclient.stopTrackingConn(conn)
			zclient.stopTrackingConn(zconn)
		} else {
			server.Lock()
			zclient, isZ := server.Zclients[string(token)]
			server.Unlock()
			if !isZ {
				log.Printf("Error token from unknown client %s %s", conn.LocalAddr(), conn.RemoteAddr())
				conn.Close()
				return
			}
			//log.Printf("Adding %p to Zpool", conn)
			zclient.Lock()
			zclient.pool.PushBack(conn)
			zclient.Unlock()
			log.Printf("Z proxy %s %s", conn.RemoteAddr(), conn.LocalAddr())
			zclient.connpool <- conn
		}

	}

}
