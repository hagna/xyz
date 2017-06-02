package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hagna/xyz/internal"
	"github.com/hashicorp/yamux"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"math"
	mathrand "math/rand"
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
)

var (
	cert_common_name     string        = "X"                    /* the common name to use in the certificate */
	heartbeatinterval                  = 2 * time.Minute        /* time between beats */
	certificate          string                                 /* file name containing a TLS ceritifcate */
	certificateauthority string                                 /* file containing certificateauthority */
	privatekey           string                                 /* file containing the private TLS key */
	authscript           string                                 /* file to exec for an authentication script */
	networkendpoint      string                                 /* the host:port or :port address */
	noverify             bool                                   /* don't verify client certs */
	version              = "dev"                                /* set by making a release */
	ARGV                 *cli.Context                           /* command line */
	idletimeout          time.Duration = 800 * time.Millisecond /* time to wait for client to say something*/
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
		isX := true
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
		cert, priv, err := xyz.CaSignedCert(cert_common_name, host, rsaBits, ecdsaCurve, validFrom, validFor, isCA, isX, &ca_key_pair)
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

	config.InsecureSkipVerify = noverify
	log.Println("setting config.InsecureSkipVerify = %s", noverify)
	/*if *servername != "" {
		config.ServerName = *servername
	}
	*/

	return config, nil
}

// urfave/cli boilerplate (it is not my fave)
func main() {
	app := cli.NewApp()
	app.Name = "X"
	app.Usage = `Make a relayed connection`
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
	app.ArgsUsage = `[options] <Y endpoint> <local server endpoint (127.0.0.1:8080 for example)> [@name]`
	app.Flags = []cli.Flag{
		cli.BoolFlag{Destination: &noverify, Name: "noverify", Usage: "Verify client side certificates"},
		cli.StringFlag{Destination: &authscript, Name: "auth, as", Usage: "Authorization script", Value: authscript},
		cli.StringFlag{Destination: &privatekey, Name: "key", Usage: "private key", Value: privatekey},
		cli.StringFlag{Destination: &cert_common_name, Name: "name", Usage: "Name of auto generated certificate (not applicable if you use key, cert, cacert)", Value: cert_common_name},
		cli.StringFlag{Destination: &certificateauthority, Name: "cacert", Usage: "ca cert", Value: certificateauthority},
		cli.StringFlag{Destination: &certificate, Name: "cert", Usage: "cert file", Value: certificate},
	}
	app.Run(os.Args)
}

type LocalServer struct {
	ln      net.Listener
	clients []net.Conn
}

// X is a server and a client; this is the server side. Change here if you want to use sockets instead of tcp
func handleLocalClient(conn net.Conn, rc *RelayClient, config *tls.Config, name string) {
	endpoint := rc.session.RemoteAddr().String()
	//log.Printf("Dialing relay for proxy requests %s\n", endpoint)

	relayconn, err := tls.Dial("tcp", endpoint, config)
	if err != nil {
		log.Printf("Error dialing relay: %s", err)
		conn.Close()
		return
	}
	_, err = xyz.Send(relayconn, rc.token)
	if err != nil {
		log.Printf("Error SendingToken: %s", err)
		conn.Close()
		relayconn.Close()
		return
	}

	_, err = xyz.Send(relayconn, []byte(name))
	if err != nil {
		log.Printf("Error sending name: %s", err)
		conn.Close()
		relayconn.Close()
		return
	}
	go xyz.ProxyConn(conn, relayconn)

}

// For sending the token request from X to Y
func makeControlConnection(config *tls.Config, endpoint string) (*RelayClient, error) {
	mathrand.Seed(time.Now().Unix())
	conn, err := tls.Dial("tcp", endpoint, config.Clone())
	if err != nil {
		return nil, err
	}
	_, err = xyz.Send(conn, []byte("TOK?"))
	if err != nil {
		log.Printf("Error writing token request: %s", err)
		conn.Close()
		return nil, err
	}
	if authscript != "" {
		cmd := exec.Command(authscript)
		out, err := cmd.Output()
		if err != nil {
			log.Printf("Could not run authscript \"%s\": %s", authscript, err)
		} else {
			_, err = xyz.Send(conn, out)
			if err != nil {
				log.Printf("Could not send output of authscript to conn: %s", err)
			}
		}
	}
	relayclient := new(RelayClient)
	relayclient.token, err = xyz.RecvWithTimeout(conn, idletimeout)
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
		x.RelayClients[string(relayclient.token)] = relayclient
		x.Unlock()
	*/
	return relayclient, nil
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
		config.ServerName = extractServername(endpoint)
	CONNECT:
		relayclient, err := makeControlConnection(config, endpoint)
		for {
			if err != nil || relayclient.session.IsClosed() {
				delay = math.Min(delay*factor, maxDelay)
				delay = mathrand.NormFloat64()*delay*jitter + delay
				backofftime := (time.Duration(int64(delay*float64(time.Second))) / time.Second) * time.Second
				log.Printf("Error %s. Trying again in %v", err, backofftime)
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

	}(config, endpoint)

	return rcChan
}

type endpoint struct {
	name          string
	localendpoint string
	relayendpoint string
}

// really main()
func action(c *cli.Context) error {
	log.SetFlags(log.Lshortfile)
	ARGV = c

	x := new(X)
	x.RelayClients = make(map[string]*RelayClient)
	if cmd := c.Args().Get(len(c.Args()) - 1); cmd == "who" {
		config, err := tlsConfig()
		if err != nil {
			fmt.Println("TLS config failed.")
			return (err)
		}
		for i := 0; i < len(c.Args())-1; i++ {
			relayendpoint := c.Args().Get(i)

			controlConnector := startControlConnector(config.Clone(), relayendpoint)
			rc := <-controlConnector

			conn, err := tls.Dial("tcp", rc.ctl.RemoteAddr().String(), config)
			if err != nil {
				log.Printf("Error dialing relay: %s", err)
				conn.Close()
				continue
			}
			defer conn.Close()
			_, err = xyz.Send(conn, []byte(rc.token))
			if err != nil {
				log.Printf("Could not send token for WHO command: %s", err)
				continue
			}
			_, err = xyz.Send(conn, []byte("WHO"))
			if err != nil {
				log.Printf("Could not send WHO command: %s", err)
				continue
			}
			res, err := xyz.Recv(conn)
			if err != nil {
				log.Printf("Could not receive WHO list: %s", err)
				continue
			}
			fmt.Println(relayendpoint)
			fmt.Println(string(res))
		}
		return nil
	}
	endpoints := []endpoint{}
	i := 0
	for {
		relayendpoint := c.Args().Get(i)
		if relayendpoint == "" {
			if i == 0 {
				return fmt.Errorf("Need relay endpoint host:port")
			} else {
				break
			}

		}
		i++
		localendpoint := c.Args().Get(i)
		if localendpoint == "" {
			return fmt.Errorf("Need local endpoint host:port")
		}
		i++
		name := c.Args().Get(i)
		if len(name) >= 1 {
			if name[0] == '@' {
				name = name[1:]
				i++
			} else {
				name = ""
			}
		}
		endpoints = append(endpoints, endpoint{name, localendpoint, relayendpoint})

	}
	config, err := tlsConfig()
	if err != nil {
		fmt.Println("TLS config failed.")
		return (err)
	}

	for _, v := range endpoints {
		name := v.name
		localendpoint := v.localendpoint
		relayendpoint := v.relayendpoint
		controlConnector := startControlConnector(config.Clone(), relayendpoint)
		ln, err := net.Listen("tcp", localendpoint)
		if err != nil {
			log.Printf("Error listening for local connection: %s", err)
			continue
		}
		//log.Println("waiting for client connection")
		go func(ln net.Listener, controlConnector <-chan *RelayClient, config *tls.Config, name string) {
			for {
				localconn, err := ln.Accept()
				if err != nil {
					log.Printf("Error accepting connection: %s", err)
				}
				relayController := <-controlConnector
				handleLocalClient(localconn, relayController, config, name)
			}
		}(ln, controlConnector, config, name)

	}
	select {}
	return nil
}

// For holding X's state
type X struct {
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
