package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hagna/xyz"
	"github.com/hashicorp/yamux"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"os"
	"sync"

	"time"
)

const (
	MESSAGELENGTH = 4
	MAXMSGLENGTH  = 2048
	TOKENLENGTH   = 1024
)

var (
	heartbeatinterval    = 2 * time.Minute   /* time between beats */
	relayidletimeout     = 100 * time.Second /* idle timeout for the local to relay connection */
	certificate          string              /* file name containing a TLS ceritifcate */
	certificateauthority string              /* file containing certificateauthority */
	privatekey           string              /* file containing the private TLS key */
	authscript           string              /* file to exec for an authentication script */
	networkendpoint      string              /* the host:port or :port address */
	noverify             bool                /* don't verify client certs */
	version              = "dev"             /* set by making a release */
	ARGV                 *cli.Context        /* command line */
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
	app.Name = "Z"
	app.Usage = `Forward client connection to a relay`
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
	app.ArgsUsage = `[options] <Y endpoint> <local client endpoint (:8080 for example)>`
	app.Flags = []cli.Flag{
		cli.BoolFlag{Destination: &noverify, Name: "noverify", Usage: "Verify client side certificates"},
		cli.StringFlag{Destination: &authscript, Name: "auth, as", Usage: "Authorization script", Value: authscript},
		cli.StringFlag{Destination: &privatekey, Name: "key", Usage: "private key", Value: privatekey},
		cli.StringFlag{Destination: &certificateauthority, Name: "cacert", Usage: "ca cert", Value: certificateauthority},
		cli.StringFlag{Destination: &certificate, Name: "cert", Usage: "cert file", Value: certificate},
	}
	app.Run(os.Args)
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
		log.Printf("WARNING truncated send [%d]%v...%v to [%d]%v...%v", len(orig), orig[:10], orig[len(orig)-10:len(orig)], len(message), message[:10], message[len(message)-10:len(message)])
	}
	n, err := stream.Write(message)
	if err != nil {
		log.Printf("writing token [%d]%s", n, string(message[:n]))
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

type LocalServer struct {
	ln      net.Listener
	clients []net.Conn
}

// X is a server and a client; this is the server side. Change here if you want to use sockets instead of tcp
func handleLocalClient(conn net.Conn, rc *RelayClient, config *tls.Config) {
	endpoint := rc.session.RemoteAddr().String()
	log.Printf("Dialing relay for proxy requests %s\n", endpoint)

	relayconn, err := tls.Dial("tcp", endpoint, config)
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
	go proxyConn(conn, relayconn)

}

func connectRelayClient(config *tls.Config, endpoint string) (*RelayClient, error) {
	mathrand.Seed(time.Now().Unix())
	conn, err := tls.Dial("tcp", endpoint, config.Clone())
	if err != nil {
		log.Println(err)
		return nil, err
	}
	_, err = send(conn, []byte("TOK?"))
	if err != nil {
		log.Printf("Error writing token request: %s", err)
		conn.Close()
		return nil, err
	}

	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = heartbeatinterval
	conf.EnableKeepAlive = true
	session, err := yamux.Client(conn, conf)
	if err != nil {
		log.Printf("Error setting up yamux client")
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

	relayclient := new(RelayClient)
	relayclient.ctl = stream
	relayclient.session = session
	relayclient.token, err = recv(stream)
	if err != nil {
		stream.Close()
		session.Close()
		conn.Close()
		log.Printf("Error reading token: %s", err)
		return nil, err
	}
	log.Printf("Control connecion established with token [%d]%v...", len(relayclient.token), string(relayclient.token[:10]))
	/*
		x.Lock()
		x.RelayClients[string(relayclient.token)] = relayclient
		x.Unlock()
	*/
	return relayclient, nil
}

// for reconnecting the yamux connection, also known as the control channel, to the relay
func startControlConnector(config *tls.Config, endpoint string) <-chan *RelayClient {
	rcChan := make(chan *RelayClient)
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
		relayclient, err := connectRelayClient(config, endpoint)
		for {
			if err != nil || relayclient.session.IsClosed() {
				delay = math.Min(delay*factor, maxDelay)
				delay = mathrand.NormFloat64()*delay*jitter + delay
				backofftime := time.Duration(int64(delay * float64(time.Second)))
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
			rcChan <- relayclient
			delay = initialDelay
			time.Sleep(200 * time.Millisecond)

		}

	}(config, endpoint)

	return rcChan
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
	z := new(Z)
	z.RelayClients = make(map[string]*RelayClient)
	for i := 0; i < len(c.Args()); i += 2 {
		relayendpoint := c.Args().Get(i)
		localendpoint := c.Args().Get(i + 1)
		if localendpoint == "" {
			log.Fatal("need local endpoint")
		}
		controlConnector := startControlConnector(config.Clone(), relayendpoint)
		go func() {
			for {
				relay := <-controlConnector
				message, err := recv(relay.ctl)
				if err != nil {
					log.Printf("Error receiving control message: %s", err)
					continue
				}
				if string(message) == "CONNECT" {
					conn, err := tls.Dial("tcp", relayendpoint, config.Clone())
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

	}
	select {}
	return nil
}

func proxyConn(rConn net.Conn, conn net.Conn) {

	timeout := relayidletimeout

	go func() {
		defer rConn.Close()
		defer conn.Close()
		for {
			buf := make([]byte, 1024)
			conn.SetDeadline(time.Now().Add(timeout))
			n, e := conn.Read(buf)
			if e != nil {
				log.Println("exiting on read", conn.RemoteAddr(), e)
				break
			} else {
				_, e1 := rConn.Write(buf[:n])
				if e1 != nil {
					log.Println("exiting on write", rConn.RemoteAddr(), e1)
					log.Println(e1)
					break
				}
			}
		}
	}()

	go func() {
		defer rConn.Close()
		defer conn.Close()
		for {
			buf := make([]byte, 1024)
			rConn.SetDeadline(time.Now().Add(timeout))
			n, e := rConn.Read(buf)
			if e != nil {
				log.Println("exiting on read", rConn.RemoteAddr(), e)
				break
			} else {
				_, e1 := conn.Write(buf[:n])
				if e1 != nil {
					log.Println("exiting on write", conn.RemoteAddr(), e1)
					break
				}
			}
		}
	}()

}

// For holding Z's state
type Z struct {
	RelayClients map[string]*RelayClient /* the connected clients live here */
	sync.Mutex                           /* protect map from multiple writes */
}

// Each client gets one
type RelayClient struct {
	token    []byte              /* identifier from the server */
	ctl      net.Conn            /* the control connection */
	connpool map[string]net.Conn /* connections stored by address */
	session  *yamux.Session      /* use this to create new streams */
}
