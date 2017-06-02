package xyz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func Ca(host string, rsaBits int, ecdsaCurve string, validFrom string, validFor time.Duration) (pem.Block, pem.Block, error) {

	a := &PkiArgs{host: host, rsaBits: rsaBits, ecdsaCurve: ecdsaCurve, validFrom: validFrom, validFor: validFor, isCA: true}
	return mkCert(a)
}

// helper for Ca and GenerateCA
func mkCert(a *PkiArgs) (pem.Block, pem.Block, error) {
	isX := a.isX
	isCA := a.isCA
	validFor := a.validFor
	validFrom := a.validFrom
	ecdsaCurve := a.ecdsaCurve
	host := a.host
	rsaBits := a.rsaBits
	parent := a.parent
	if len(host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	priv, err := mkKey(ecdsaCurve, rsaBits)

	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if isX {
		template.Subject.OrganizationalUnit = []string{"X"}
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	if parent == nil {
		parent = template
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	return pem.Block{Type: "CERTIFICATE", Bytes: derBytes}, *pemBlockForKey(priv), nil

}

// help getMax
var not_a_number = regexp.MustCompile(`[^\d+]`)

func tonum(a string) int {
	s := not_a_number.ReplaceAll([]byte(a), []byte(""))
	i, err := strconv.Atoi(string(s))
	if err != nil {
		log.Printf("Warning to Atoi: %s %s", a, err)
	}
	return i
}

// find the right number for naming next cert in pwd
func getMaxName() string {
	l, err := filepath.Glob("*.cert")
	if err != nil {
		log.Fatalf("failed to Glob *.pem: %s", err)
	}
	res := []int{}
	for _, k := range l {
		res = append(res, tonum(k))
	}
	max := 0
	for _, p := range res {
		if p > max {
			max = p
		}
	}
	return fmt.Sprintf("%d", max+1)
}

// helper for making the key
func mkKey(ecdsaCurve string, rsaBits int) (interface{}, error) {
	var priv interface{}
	var err error
	switch ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", ecdsaCurve)
		os.Exit(1)
	}
	return priv, err
}

type PkiArgs struct {
	cname      string
	host       string
	rsaBits    int
	ecdsaCurve string
	validFrom  string
	validFor   time.Duration
	isCA       bool
	isX        bool
	ca         *tls.Certificate
	parent     *x509.Certificate
}

// helpd GenerateSignedCertificate create a csr etc.
func mkSignedCert(a *PkiArgs) (pem.Block, pem.Block, error) {
	ca := a.ca
	isX := a.isX
	isCA := a.isCA
	cname := a.cname
	validFor := a.validFor
	validFrom := a.validFrom
	ecdsaCurve := a.ecdsaCurve
	host := a.host
	rsaBits := a.rsaBits
	parents, e := x509.ParseCertificates(ca.Certificate[0])
	if e != nil {
		log.Fatalf("could not parse ca certificate: %s", e)
	}
	parent := parents[0]
	if len(host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	priv, err := mkKey(ecdsaCurve, rsaBits)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	// CSR

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"xyz"},
			CommonName:   cname,
		},
		PublicKey:          publicKey(priv),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,

		//		DNSNames:           []string{""},
		EmailAddresses: []string{"email"},
	}

	if isX {
		csrTemplate.Subject.OrganizationalUnit = []string{"X"}
	}
	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			csrTemplate.IPAddresses = append(csrTemplate.IPAddresses, ip)
		} else {
			csrTemplate.DNSNames = append(csrTemplate.DNSNames, h)
		}
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv)
	if err != nil {
		log.Fatalf("failed to create CSR: %s", err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		log.Fatalf("failed to parse certificate request: %s", err)
	}

	if err := csr.CheckSignature(); err != nil {
		log.Fatalf("CheckSignature on CSR failed %s", err)
	}
	// cert

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		Issuer:  parent.Subject,
		Subject: csr.Subject,

		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	hosts = strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey(priv), ca.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	return pem.Block{Type: "CERTIFICATE", Bytes: derBytes}, *pemBlockForKey(priv), nil
}

// Create signed cert from ca
func CaSignedCert(cname string, host string, rsaBits int, ecdsaCurve string, validFrom string, validFor time.Duration, isCA bool, isX bool, ca *tls.Certificate) (pem.Block, pem.Block, error) {
	if ca == nil {
		parentcert, e := ioutil.ReadFile("0.cert")
		if e != nil {
			log.Fatal(e)
		}
		k, e := ioutil.ReadFile("0.key")
		caval, err := tls.X509KeyPair(parentcert, k)
		ca = &caval
		if err != nil {
			log.Fatalf("Failed to get parent cert: %s", err)
		}
	}

	cert, priv, err := mkSignedCert(&PkiArgs{cname: cname, host: host, rsaBits: rsaBits, ecdsaCurve: ecdsaCurve, validFrom: validFrom, validFor: validFor, isCA: isCA, ca: ca, isX: isX})
	if err != nil {
		log.Fatalf("failed to make signed cert %s", err)
	}
	return cert, priv, nil
}

// Sign a certificate with parent certificate
func GenerateSignedCertificate(c *cli.Context) error {
	host := c.String("host")

	rsaBits := c.Int("rsa-bits")
	ecdsaCurve := c.String("ecdsa-curve")

	validFrom := c.String("start-date")

	validFor := c.Duration("duration")
	isCA := c.Bool("ca")
	isX := c.Bool("x")
	cname := c.String("cname")

	cert, priv, err := CaSignedCert(cname, host, rsaBits, ecdsaCurve, validFrom, validFor, isCA, isX, nil)
	keyno := getMaxName()
	var certname = keyno + ".cert"
	var keyname = keyno + ".key"

	certout, err := os.Create(certname)
	if err != nil {
		log.Fatalf("failed to open "+certname+" for writing: %s", err)
	}
	pem.Encode(certout, &cert)
	certout.Close()
	log.Print("written " + certname + "\n")

	keyout, err := os.OpenFile(keyname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open "+keyname+" for writing:", err)
		return nil
	}
	pem.Encode(keyout, &priv)
	keyout.Close()
	log.Print("written " + keyname + "\n")
	return nil
}

// Put a new CA key pair in 0.cert and 0.key
func GenerateCA(c *cli.Context) error {
	host := c.String("host")

	rsaBits := c.Int("rsa-bits")
	ecdsaCurve := c.String("ecdsa-curve")

	validFrom := c.String("start-date")

	validFor := c.Duration("duration")
	cert, key, err := Ca(host, rsaBits, ecdsaCurve, validFrom, validFor)
	if err != nil {
		log.Fatalf("failed to create certificate: %s", err)
	}
	var certname = "0.cert"
	var keyname = "0.key"

	certout, err := os.Create(certname)
	if err != nil {
		log.Fatalf("failed to open "+certname+" for writing: %s", err)
	}
	pem.Encode(certout, &cert)
	certout.Close()
	log.Print("written " + certname + "\n")

	keyout, err := os.OpenFile(keyname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open "+keyname+" for writing:", err)
		return nil
	}
	pem.Encode(keyout, &key)
	keyout.Close()
	log.Print("written " + keyname + "\n")
	return nil
}
