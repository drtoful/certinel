package certinel

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoPeerCertificate = errors.New("peer did not present certificate for domain")
	ErrExpired           = errors.New("certificate expired")
	ErrNotYetValid       = errors.New("certificate not yet valid")
	ErrInvalidHostname   = errors.New("invalid hostname")
	ErrNoCertificate     = errors.New("certificate serial not found")
)

var checkers struct {
	sync.Mutex
	state map[string]bool
}

func init() {
	checkers.state = make(map[string]bool)
}

type Domain struct {
	Domain string `json:"domain"`
	Port   string `json:"port"`
	cert   *x509.Certificate
}

type Status struct {
	Duration int64  `json:"check_duration"`
	Valid    bool   `json:"valid"`
	Err      string `json:"last_error"`
	Time     string `json:"last_check"`
	Validity int    `json:"valid_days"`
}

type Subject struct {
	CommonName         string   `json:"cn"`
	Country            []string `json:"c,omitempty"`
	Organization       []string `json:"o,omitempty"`
	OrganizationalUnit []string `json:"ou,omitempty"`
}

type Signature struct {
	Algorithm int    `json:"algorithm"`
	Value     string `json:"value"`
}

type Certificate struct {
	NotBefore      time.Time         `json:"not_before"`
	NotAfter       time.Time         `json:"not_after"`
	Issuer         Subject           `json:"issuer"`
	Subject        Subject           `json:"subject"`
	SerialNumber   string            `json:"serial"`
	AlternateNames []string          `json:"alternate_names,omitempty"`
	Signature      Signature         `json:"signature"`
	Fingerprints   map[string]string `json:"fingerprints"`
}

func toHexString(data []byte) string {
	result := make([]string, len(data))
	for i := 0; i < len(data); i += 1 {
		result[i] = hex.EncodeToString(data[i : i+1])
	}
	return strings.Join(result, ":")
}

func convertCert(cert *x509.Certificate) *Certificate {
	result := &Certificate{
		NotBefore:      cert.NotBefore.UTC(),
		NotAfter:       cert.NotAfter.UTC(),
		SerialNumber:   toHexString(cert.SerialNumber.Bytes()),
		AlternateNames: cert.DNSNames,
		Fingerprints:   make(map[string]string),
	}

	result.Signature = Signature{
		Value:     toHexString(cert.Signature),
		Algorithm: int(cert.SignatureAlgorithm),
	}

	result.Subject = Subject{
		CommonName:         cert.Subject.CommonName,
		Country:            cert.Subject.Country,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
	}

	result.Issuer = Subject{
		CommonName:         cert.Issuer.CommonName,
		Country:            cert.Issuer.Country,
		Organization:       cert.Issuer.Organization,
		OrganizationalUnit: cert.Issuer.OrganizationalUnit,
	}

	s256 := sha256.New()
	s256.Write(cert.Raw)
	result.Fingerprints["sha256"] = toHexString(s256.Sum(nil))

	s1 := sha1.New()
	s1.Write(cert.Raw)
	result.Fingerprints["sha1"] = toHexString(s1.Sum(nil))

	return result
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
	// dial the remote server with timeout
	c, err := net.DialTimeout("tcp", d.Domain+":"+d.Port, time.Second*10)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,     // we check expiration and hostname afterwars, we're only interested in the presented certificate
		ServerName:         d.Domain, // Set the ServerName to support checking vHost certs using SNI
	})
	if conn == nil {
		return nil, err
	}

	// make sure the handshake will timeout so the check will return
	// at some point
	if err := conn.SetDeadline(time.Now().Add(time.Second * 10)); err != nil {
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
		return err
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
		id := d.cert.NotBefore.Format(time.RFC3339)
		data := base64.StdEncoding.EncodeToString(d.cert.Raw)
		if err := store.Set(bucket, "cert~"+d.cert.SerialNumber.String(), data); err != nil {
			return err
		}

		if err := store.Set(bucket, "history~"+id, d.cert.SerialNumber.String()); err != nil {
			return err
		}

		if err := store.Set(bucket, "history~~", "-- LIST STOP --"); err != nil {
			return err
		}

		if err := store.Set(bucket, "current", d.cert.SerialNumber.String()); err != nil {
			return err
		}
	}

	if status != nil {
		data, err := json.Marshal(status)
		if err != nil {
			return err
		}
		if err := store.Set(bucket, "status", string(data)); err != nil {
			return err
		}
	}

	return nil
}

func (d *Domain) Status() (*Status, error) {
	rhost, err := ReverseHost(d.Domain)
	if err != nil {
		return nil, err
	}

	store := GetStore()
	bucket := []string{"domains", rhost + ":" + d.Port}
	value, err := store.Get(bucket, "status")
	if err != nil {
		return nil, err
	}

	data := &Status{}
	if err := json.Unmarshal([]byte(value), data); err != nil {
		return nil, err
	}

	return data, nil
}

func (d *Domain) Delete() error {
	rhost, err := ReverseHost(d.Domain)
	if err != nil {
		return err
	}

	store := GetStore()
	if err := store.Remove([]string{"domains"}, rhost+":"+d.Port); err != nil {
		return err
	}

	checkers.Lock()
	delete(checkers.state, d.Domain+":"+d.Port)
	checkers.Unlock()

	return nil
}

func (d *Domain) CertList() (*Certificate, []*Certificate, error) {
	rhost, err := ReverseHost(d.Domain)
	if err != nil {
		return nil, nil, err
	}

	store := GetStore()
	bucket := []string{"domains", rhost + ":" + d.Port}
	curr, err := store.Get(bucket, "current")
	if err != nil {
		return nil, nil, err
	}

	current, err := d.LoadCertificate(curr)
	if err != nil {
		return nil, nil, err
	}

	his := store.Scan(bucket, "history~", true, 51)
	history := make([]*Certificate, 0)
	for kv := range his {
		if len(kv.Value) > 0 {
			cert, err := d.LoadCertificate(kv.Value)
			if err == nil {
				history = append(history, cert)
			}
		}
	}

	return current, history, nil
}

func (d *Domain) LoadCertificate(serial string) (*Certificate, error) {
	rhost, err := ReverseHost(d.Domain)
	if err != nil {
		return nil, err
	}

	store := GetStore()
	bucket := []string{"domains", rhost + ":" + d.Port}
	raw, err := store.Get(bucket, "cert~"+serial)
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, ErrNoCertificate
	}

	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return convertCert(cert), nil
}

func CheckDomain(domain, port string) {
	ticker := time.NewTicker(time.Minute * 5)
	log.Printf("starting domain checker for \"%s:%s\"\n", domain, port)

	checkers.Lock()
	checkers.state[domain+":"+port] = true
	checkers.Unlock()

	for {
		checkers.Lock()
		v, ok := checkers.state[domain+":"+port]
		checkers.Unlock()

		if !v || !ok {
			log.Printf("stopping check on \"%s:%s\"\n", domain, port)
			break
		}

		d := &Domain{
			Domain: domain,
			Port:   port,
		}

		start := time.Now()
		status := &Status{Time: start.UTC().Format(time.RFC3339)}
		err := d.Check()
		if err != nil {
			log.Printf("checking domain \"%s:%s\": %s\n", domain, port, err.Error())
			status.Valid = false
			status.Err = err.Error()
			AddMetricPoint(d.Domain, d.Port, 0, err)
		} else {
			now := time.Now().UTC().Unix()
			validity := d.cert.NotAfter.Unix() - now
			status.Valid = true
			status.Validity = int(validity / 86400)
			log.Printf("checking domain \"%s:%s\": certificate is valid for %d days", domain, port, status.Validity)
			AddMetricPoint(d.Domain, d.Port, float64(validity), nil)
		}
		status.Duration = int64(time.Since(start) / time.Millisecond)

		// store latest check and certificate
		d.Store(status)

		// wait for 5 minutes
		<-ticker.C
	}
}

func GetDomains() []*Domain {
	result := make([]*Domain, 0)
	store := GetStore()
	for kv := range store.Scan([]string{"domains"}, "", false, 0) {
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
