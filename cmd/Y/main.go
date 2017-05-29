package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/hagna/xyz/internal"
	"github.com/hashicorp/yamux"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	MESSAGELENGTH = 4
	MAXMSGLENGTH  = 2048
	TOKENLENGTH   = 1024
	NAMELENGTH    = 10
	PROXYCHUNK    = 1024
)

var (
	pruneclientinterval  = 1 * time.Minute                          /* idle timeout for the local to relay connection */
	certificate          string                                     /* file name containing a TLS ceritifcate */
	certificateauthority string                                     /* file containing certificateauthority */
	privatekey           string                                     /* file containing the private TLS key */
	authscript           string                                     /* file to exec for an authentication script */
	networkendpoint      string                                     /* the host:port or :port address */
	noverify             bool                                       /* don't verify client certs */
	heartbeatinterval    time.Duration     = 2 * time.Minute        /* time between beats */
	idletimeout          time.Duration     = 800 * time.Millisecond /* time to wait for client to say something*/
	version                                = "dev"                  /* set by making a release */
	ARGV                 *cli.Context                               /* command line */
)

// either use the given values for cert key and ca or generate them anew
func getTLScerts(c, k, ca string) ([]byte, []byte, []byte, error) {
	res := [][]byte{}
	var err error
	var a []byte
	for _, l := range []string{c, k, ca} {
		a, err = ioutil.ReadFile(l)
		if err != nil {
			log.Printf("getTLScerts failed to load file %s: %s", l, err)
			break
		}
		res = append(res, a)
	}
	if err != nil {
		isX := false
		host := "host"
		rsaBits := 2048
		ecdsaCurve := ""
		validFor := 365 * 24 * time.Hour
		validFrom := ""
		isCA := true
		log.Println("creating CA")
		cacert, cakey, err := xyz.Ca(host, rsaBits, ecdsaCurve, validFrom, validFor)
		if err != nil {
			log.Fatalf("failed to create certificate: %s", err)
		}
		ca_key_pair, err := tls.X509KeyPair(pem.EncodeToMemory(&cacert), pem.EncodeToMemory(&cakey))
		if err != nil {
			log.Fatalf("failed to make ca key pair: %s", err)
		}
		log.Println("creating certificate")
		isCA = false
		cert, priv, err := xyz.CaSignedCert(host, rsaBits, ecdsaCurve, validFrom, validFor, isCA, isX, &ca_key_pair)
		if err != nil {
			log.Fatalf("failed to make signed cert %s", err)
		}
		return pem.EncodeToMemory(&cert), pem.EncodeToMemory(&priv), pem.EncodeToMemory(&cacert), nil
	}
	return res[0], res[1], res[2], nil
}

// TLS setup
func tlsConfig() (*tls.Config, error) {

	c, k, ca, err := getTLScerts(certificate, privatekey, certificateauthority)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(c, k)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	config := &tls.Config{
		Rand:         rand.Reader,
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	config.BuildNameToCertificate()

	if noverify {
		config.InsecureSkipVerify = true
	}
	/*if *servername != "" {
		config.ServerName = *servername
	}
	*/

	return config, nil
}

// urfave/cli boilerplate (it is not my fave)
func main() {
	app := cli.NewApp()
	app.Name = "Y"
	app.Usage = `Relay a connection`
	app.Version = version
	app.Action = action
	app.Commands = []cli.Command{
		{
			Name:   "newca",
			Action: xyz.GenerateCA,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "host", Usage: "Comma-separated hostnames and IPs to generate a certificate for"},

				cli.StringFlag{Name: "start-date", Value: "", Usage: "Creation date formatted as Jan 1 15:04:05 2011"},

				cli.StringFlag{Name: "ecdsa-curve", Value: "", Usage: "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521"},
				cli.DurationFlag{Name: "duration", Value: 365 * 24 * time.Hour, Usage: "Duration that certificate is valid for"},
				cli.IntFlag{Name: "rsa-bits", Value: 2048, Usage: "Size of RSA key to generate. Ignored if --ecdsa-curve is set"},
			},
		},
		{
			Name:   "newcert",
			Action: xyz.GenerateSignedCertificate,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "host", Usage: "Comma-separated hostnames and IPs to generate a certificate for"},

				cli.StringFlag{Name: "start-date", Value: "", Usage: "Creation date formatted as Jan 1 15:04:05 2011"},

				cli.StringFlag{Name: "ecdsa-curve", Value: "", Usage: "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521"},
				cli.DurationFlag{Name: "duration", Value: 365 * 24 * time.Hour, Usage: "Duration that certificate is valid for"},
				cli.BoolFlag{Name: "ca", Usage: "whether this cert should be its own Certificate Authority"},
				cli.BoolFlag{Name: "x", Usage: "Set OU to X for certs from X"},
				cli.IntFlag{Name: "rsa-bits", Value: 2048, Usage: "Size of RSA key to generate. Ignored if --ecdsa-curve is set"},
			},
		},
	}
	app.ArgsUsage = `[options] <endpoint>`
	app.Flags = []cli.Flag{
		cli.BoolFlag{Destination: &noverify, Name: "noverify", Usage: "Do not verify from the client certificates"},
		cli.StringFlag{Destination: &authscript, Name: "auth, as", Usage: "Authorization script", Value: authscript},
		cli.StringFlag{Destination: &privatekey, Name: "key", Usage: "private key", Value: privatekey},
		cli.StringFlag{Destination: &certificateauthority, Name: "cacert", Usage: "ca cert", Value: certificateauthority},
		cli.StringFlag{Destination: &certificate, Name: "cert", Usage: "cert file", Value: certificate},
	}
	app.Run(os.Args)
}

// Use this to identify authentic clients
type AuthInfo struct {
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
	ctl      net.Conn            /* the control connection */
	pool     map[string]net.Conn /* all the connections */
	session  *yamux.Session      /* use this to create new streams */
	authinfo *AuthInfo
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

// for removing the conn from the list
func (c *client) stopTrackingConn(ref string) error {
	c.Lock()
	_, ok := c.pool[ref]
	if !ok {
		log.Printf("BUGBUG no conn by the name %s", ref)
	} else {
		log.Printf("Stop tracking connection %s", ref)
	}
	c.Unlock()
	return nil
}

// for destroying all the connections corresponding to one client
func (c *client) Close() error {
	var deleteme []string
	for _, v := range c.pool {
		v.Close()
		name := fmt.Sprintf("%p", v)
		_, ok := c.pool[name]
		if !ok {
			log.Printf("BUGBUG no conn by the name %s", name)
		}
		deleteme = append(deleteme, name)

	}
	for _, v := range deleteme {
		conn, ok := c.pool[v]
		if !ok {
			log.Printf("BUGBUG no conn by the name %s", v)
		} else {
			log.Printf("Closing conn %p", conn)
			conn.Close()
		}
		delete(c.pool, v)
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
				log.Printf("%s has closed so closing connections", v.authinfo.name)
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
				log.Printf("%s has closed so closing connections", v.authinfo.name)
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
func (*Relay) Authenticate(conn net.Conn) (*AuthInfo, error) {
	authinfo := new(AuthInfo)
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("Auth failed could not cast to TLS connection")
	}
	cs := tconn.ConnectionState()
	log.Printf("\tPeerCertificates:")
	for i, v := range cs.PeerCertificates {
		authinfo.name = v.Subject.CommonName
		z := v.Subject.OrganizationalUnit
		ou := ""
		if len(z) >= 1 {
			ou = z[0]
		}
		log.Printf("\t\t%d: %+v\n", i, v.Subject)
		if ou == "X" {
			authinfo.isX = true
			break
		}
	}
	log.Printf("\tVerified chains:")
	for i, v := range cs.VerifiedChains {
		log.Printf("\t\t%d: %+v\n", i, v)
	}
	if cs.VerifiedChains == nil {
		if authscript != "" {
			cookie, err := xyz.RecvWithTimeout(conn, idletimeout)
			if err != nil {
				return nil, fmt.Errorf("Auth failed: %s", err)
			}
			cmd := exec.Command(authscript)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return nil, fmt.Errorf("Auth failed: %s", err)
			}
			fmt.Fprintf(stdin, string(cookie))
			out, err := cmd.Output()
			if err != nil {
				return nil, fmt.Errorf("Auth failed: %s", err)
			}
			name := string(out)
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
		} else {
			if !noverify {
				return nil, fmt.Errorf("Could not authenticate with certificate")
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

// make the control connection
func (server *Relay) makeControlConnection(conn net.Conn) error {
	authinfo, err := server.Authenticate(conn)
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
	log.Println("accepted yamux stream")
	token, err := nRandomBytes64(TOKENLENGTH)
	if err != nil {
		stream.Close()
		session.Close()
		conn.Close()
		return err
	}
	_, err = xyz.Send(stream, token)
	if err != nil {
		stream.Close()
		session.Close()
		conn.Close()
		return err
	}
	ttype := "Z"
	if authinfo.isX {
		ttype = "X"
		client := new(Xclient)
		client.ctl = stream
		client.authinfo = authinfo
		client.session = session
		client.pool = make(map[string]net.Conn)
		server.Lock()
		server.Xclients[string(token)] = client
		server.Unlock()
	} else {
		client := new(Zclient)
		client.connpool = make(chan net.Conn)
		client.ctl = stream
		client.authinfo = authinfo
		client.session = session
		client.pool = make(map[string]net.Conn)
		server.Lock()
		server.Zclients[string(token)] = client
		server.Unlock()
	}

	log.Printf("%s: token request %s", ttype, conn.RemoteAddr())

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
func (server *Relay) HandleConn(conn *tls.Conn) {
	message, err := xyz.RecvWithTimeout(conn, idletimeout)
	if err != nil {
		log.Printf("Client \"%v\" did not send quickly enough: %s", conn.RemoteAddr(), err.Error())
		conn.Close()
		return
	}
	switch string(message) {
	case "TOK?":
		err := server.makeControlConnection(conn)
		if err != nil {
			log.Printf("Could not make control connection: %v", err)
		}
	default:
		token := message
		if err != nil {
			log.Printf("Could not read token: %v", err)
			return
		}
		if len(token) < TOKENLENGTH {
			log.Printf("Token too short: %v", token)
			conn.Close()
		}

		server.Lock()
		xclient, isX := server.Xclients[string(token)]
		server.Unlock()
		conntype := "X"
		if !isX {
			conntype = "Z"
		}
		log.Printf("New %s: (%v...%v) len %d", conntype, string(message[:10]), string(message[len(message)-10:len(message)]), len(message))
		if isX {
			b, err := xyz.RecvWithTimeout(conn, idletimeout)
			name := string(b)
			if err != nil {
				log.Printf("Error receiving name from %s: %s", conn.RemoteAddr(), err)
			}
			if name == "WHO" {
				tosend := []byte{}
				for _, v := range server.whoList() {
					tosend = append(tosend, []byte(v+"\n")...)
				}

				_, err := xyz.Send(conn, tosend)
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
				log.Printf("sending %s", m)
				_, _ = conn.Write([]byte(m))
				conn.Close()
				return
			}
			server.Unlock()

			zclient := new(Zclient)
			server.Lock()
			for _, v := range server.Zclients {
				log.Printf("Does zclient \"%s\" match \"%s\"", v.authinfo.name, name)
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
				log.Printf("Even though X wanted \"%s\" Y is connecting the only Z it has \"%s\"", name, zclient.authinfo.name)
			}

			server.Unlock()
			_, err = xyz.Send(zclient.ctl, []byte("CONNECT"))
			if err != nil {
				log.Printf("Error sending connect message to Z: %s", err)
				conn.Close()
				return
			}
			connid := fmt.Sprintf("%p", conn)
			zconn := <-zclient.connpool
			zconnid := fmt.Sprintf("%p", zconn)
			log.Printf("Adding %p to Xpool", conn)
			xclient.Lock()
			xclient.pool[connid] = conn
			xclient.Unlock()
			xyz.ProxyConn(conn, zconn)
			log.Printf("Proxy started between Z (%p) and X (%p)", zconn, conn)
			xclient.stopTrackingConn(connid)
			zclient.stopTrackingConn(zconnid)
		} else {
			server.Lock()
			zclient, isZ := server.Zclients[string(token)]
			server.Unlock()
			if !isZ {
				log.Printf("Error received token from unknown client")
				conn.Close()
				return
			}
			log.Printf("Adding %p to Zpool", conn)
			zclient.Lock()
			zclient.pool[fmt.Sprintf("%p", conn)] = conn
			zclient.Unlock()
			zclient.connpool <- conn
		}
	}

}

// really main()
func action(c *cli.Context) error {
	log.SetFlags(log.Lshortfile)
	ARGV = c
	config, err := tlsConfig()
	if err != nil {
		fmt.Println("TLS config failed.")
		return (err)
	}
	relay := new(Relay)
	relay.Xclients = make(map[string]*Xclient)
	relay.Zclients = make(map[string]*Zclient)
	go relay.pruneClients()
	for _, networkendpoint := range c.Args() {
		ln, err := tls.Listen("tcp", networkendpoint, config)
		if err != nil {
			log.Fatal(err)
		}
		relay.listener = ln
		log.Printf("listening on %s\n", ln.Addr().String())
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println("error on Accept:", err)
					continue
				}
				tconn, ok := conn.(*tls.Conn)
				if !ok {
					log.Println("Not a TLS connection")
					continue
				}
				go relay.HandleConn(tconn)
			}
		}(ln)
	}
	select {}
	return nil
}
