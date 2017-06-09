package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hagna/xyz"
	"github.com/hagna/xyz/internal"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const (
	MESSAGELENGTH = 4
	MAXMSGLENGTH  = 2048
	TOKENLENGTH   = 1024
)

var (
	cert_common_name     string        = "Z"                    /* the common name to use in the certificate */
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
		isX := false
		host := "host"
		rsaBits := 2048
		ecdsaCurve := ""
		validFor := 365 * 24 * time.Hour
		validFrom := ""
		isCA := true
		log.Println("creating CA")
		cacert, cakey, err := internal.Ca(host, rsaBits, ecdsaCurve, validFrom, validFor)
		if err != nil {
			log.Fatalf("failed to create certificate: %s", err)
		}
		ca_key_pair, err := tls.X509KeyPair(pem.EncodeToMemory(&cacert), pem.EncodeToMemory(&cakey))
		if err != nil {
			log.Fatalf("failed to make ca key pair: %s", err)
		}
		log.Println("creating certificate")
		isCA = false
		cert, priv, err := internal.CaSignedCert(cert_common_name, host, rsaBits, ecdsaCurve, validFrom, validFor, isCA, isX, &ca_key_pair)
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

	config.InsecureSkipVerify = noverify
	config.BuildNameToCertificate()
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
			Action: internal.GenerateCA,
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
			Action: internal.GenerateSignedCertificate,
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
		cli.StringFlag{Destination: &cert_common_name, Name: "cname", Usage: "Name of auto generated certificate", Value: cert_common_name},
		cli.StringFlag{Destination: &privatekey, Name: "key", Usage: "private key", Value: privatekey},
		cli.StringFlag{Destination: &certificateauthority, Name: "cacert", Usage: "ca cert", Value: certificateauthority},
		cli.StringFlag{Destination: &certificate, Name: "cert", Usage: "cert file", Value: certificate},
	}
	app.Run(os.Args)
}

type endpoint struct {
	localendpoint string
	relayendpoint string
}

// really main()
func action(c *cli.Context) error {

	if version == "dev" {
		log.SetFlags(log.Lshortfile | log.Ltime)
	}
	if len(c.Args()) < 2 {
		log.Fatal("Need at least two arguments")
	}
	ARGV = c

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
		endpoints = append(endpoints, endpoint{localendpoint, relayendpoint})

	}
	config, err := tlsConfig()
	if err != nil {
		fmt.Println("TLS config failed.")
		return (err)
	}
	for _, v := range endpoints {
		localendpoint := v.localendpoint
		relayendpoint := v.relayendpoint
		_, err := xyz.StartZ(config, authscript, localendpoint, relayendpoint)
		if err != nil {
			log.Fatal(err)
		}
	}
	select {}
	return nil
}
