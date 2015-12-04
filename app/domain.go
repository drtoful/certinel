package certinel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoPeerCertificate = errors.New("peer did not present certificate for domain")
	ErrExpired           = errors.New("certificate expired")
	ErrNotYetValid       = errors.New("certificate not yet valid")
	ErrInvalidHostname   = errors.New("invalid hostname")
)

type Domain struct {
	Domain string `json:"domain"`
	Port   string `json:"port"`
	cert   *x509.Certificate
}

type Status struct {
	Duration int64  `json:"duration"`
	Valid    bool   `json:"valid"`
	Err      string `json:"error"`
}

// reverse a hostname (example.com => com.example.). This will provide a better
// form for sorting (www.example.com and api.example.com will be close together
// when reversed)
func ReverseHost(hostname string) (string, error) {
	if _, ok := dns.IsDomainName(hostname); ok {
		labels := dns.SplitDomainName(hostname)

		for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
			labels[i], labels[j] = labels[j], labels[i]
		}

		return strings.Join(labels, "."), nil
	} else {
		return "", ErrInvalidHostname
	}

	return "", ErrInvalidHostname
}

func (d *Domain) GetCertificate() (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", d.Domain+":"+d.Port, nil)
	if err != nil {
		return nil, err
	}

	if err := conn.Handshake(); err != nil {
		return nil, err
	}

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		if ok := cert.VerifyHostname(d.Domain); ok == nil {
			return cert, nil
		}
	}

	return nil, ErrNoPeerCertificate
}

func (d *Domain) Check() error {
	cert, err := d.GetCertificate()
	if err != nil {
		return nil
	}
	d.cert = cert

	now := time.Now().UTC()
	if !now.Before(cert.NotAfter) {
		return ErrExpired
	}

	if !now.After(cert.NotBefore) {
		return ErrNotYetValid
	}

	return nil
}

func (d *Domain) Store(status *Status) error {
	rhost, err := ReverseHost(d.Domain)
	if err != nil {
		return err
	}

	store := GetStore()
	bucket := []string{"domains", rhost + ":" + d.Port}
	if err := store.Create(bucket); err != nil {
		return err
	}

	if d.cert != nil {
		data := base64.StdEncoding.EncodeToString(d.cert.Raw)
		if err := store.Set(bucket, "cert~"+d.cert.SerialNumber.String(), data); err != nil {
			return err
		}
	}

	if status != nil {
		data, err := json.Marshal(status)
		if err != nil {
			return err
		}
		return store.Set(bucket, "status~"+d.cert.SerialNumber.String(), string(data))
	}

	return nil
}

func (d *Domain) Delete() error {
	rhost, err := ReverseHost(d.Domain)
	if err != nil {
		return err
	}

	store := GetStore()
	return store.Remove([]string{"domains"}, rhost+":"+d.Port)
}

func CheckDomain(domain, port string) {
	ticker := time.NewTicker(time.Minute * 5)
	log.Printf("starting domain checker for \"%s:%s\"\n", domain, port)

	for {
		<-ticker.C

		d := &Domain{
			Domain: domain,
			Port:   port,
		}

		start := time.Now()
		status := &Status{}
		err := d.Check()
		if err != nil {
			log.Printf("checking domain \"%s:%s\": %s\n", domain, port, err.Error())
			status.Valid = false
			status.Err = err.Error()
		} else {
			now := time.Now().UTC().Unix()
			validity := int((d.cert.NotAfter.Unix() - now) / 86400)
			log.Printf("checking domain \"%s:%s\": certificate is valid for %d days", domain, port, validity)
			status.Valid = true
		}
		status.Duration = int64(time.Since(start) / time.Millisecond)

		// store latest check and certificate
		d.Store(status)
	}
}

func GetDomains() []*Domain {
	result := make([]*Domain, 0)
	store := GetStore()
	for kv := range store.Scan([]string{"domains"}, "", false) {
		splitter := strings.Split(kv.Key, ":")
		if len(splitter) != 2 {
			continue
		}

		domain, err := ReverseHost(splitter[0])
		if err != nil {
			continue
		}

		result = append(result, &Domain{Domain: domain, Port: splitter[1]})
	}

	return result
}

func StartDomainChecker() {
	for _, d := range GetDomains() {
		go CheckDomain(d.Domain, d.Port)
	}
}
