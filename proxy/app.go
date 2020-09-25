package proxy

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"log"
	"myProxy/model"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
)

type BodyWriteCloser interface {
	NewWriteCloser(*http.Response) (io.WriteCloser, error)
}

type ProxiedRequest struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	Response       *http.Response
}

type Proxy struct {
	db *sql.DB
	ln net.Listener
	// Standard HTTP server
	srv http.Server
	// RoundTrip to proxied service
	rt http.RoundTripper
	// Writer functions.
	writers []BodyWriteCloser
	// config
	sTlsConfig *tls.Config
	cTlsConfig *tls.Config
}

func NewProxy(db *sql.DB) *Proxy {
	return &Proxy{
		db: db,
		cTlsConfig: &tls.Config{
			// TODO было true
			InsecureSkipVerify: true,
		},
		sTlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
}

func (p *Proxy) HandleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.https(w, r)
	} else {
		p.http(w, r)
	}
}

func (p *Proxy) https(w http.ResponseWriter, r *http.Request) {
	//defer r.Body.Close()
	name, _, err := net.SplitHostPort(r.Host)
	var sTlsConn *tls.Conn
	if err != nil || name == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	// получить сертификат
	provisionalCert, err := certificateLookupByName(name)
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sLocalTlsConfig := new(tls.Config)
	if p.sTlsConfig != nil {
		*sLocalTlsConfig = *p.sTlsConfig
	}
	sLocalTlsConfig.Certificates = []tls.Certificate{*provisionalCert}
	sLocalTlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cLocalTlsConfig := new(tls.Config)
		if p.cTlsConfig != nil {
			*cLocalTlsConfig = *p.cTlsConfig
		}
		cLocalTlsConfig.ServerName = hello.ServerName
		sTlsConn, err = tls.Dial("tcp", r.Host, cLocalTlsConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}
		return certificateLookupByName(hello.ServerName)
	}

	// получить соединение
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	cRawConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	helloString := []byte("HTTP/1.1 200 Connection Established\r\n" +
		"Proxy-agent: Golang-Proxy\r\n" +
		"\r\n")
	if _, err = cRawConn.Write(helloString); err != nil {
		log.Println("handshake", r.Host, err)
		cRawConn.Close()
		return
	}
	cTlsConn := tls.Server(cRawConn, sLocalTlsConfig)
	err = cTlsConn.Handshake()
	if err != nil {
		log.Println("handshake", r.Host, err)
		cTlsConn.Close()
		cRawConn.Close()
		return
	}
	defer cTlsConn.Close()

	if sTlsConn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer sTlsConn.Close()

	od := &oneShotDialer{c: sTlsConn}
	rp := &httputil.ReverseProxy{
		Director:      httpsDirector,
		Transport:     &http.Transport{DialTLS: od.Dial},
	}

	ch := make(chan int)
	wc := &onCloseConn{cTlsConn, func() { ch <- 0 }}
	http.Serve(&oneShotListener{wc}, p.Wrap(rp))
	<-ch
}

func (p *Proxy) Wrap(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := model.RequestToSave{
			Host:     r.Host,
			Url:     r.URL.Path,
			Headers: map[string][]string{},
			URLParams: map[string][]string{},
			Body:    "",
			Proto:    "https",
			Method:   r.Method,
		}

		bodyByte, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println("cannot read body " + r.Host)
			http.Error(w, "no upstream", 503)
			return
		}
		req.Body = string(bodyByte)
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyByte))
		for kHeader, vHeader := range r.Header {
			if kHeader != "Proxy-Connection" {
				req.Headers[kHeader] = []string{}
				for _, v := range vHeader {
					req.Headers[kHeader] = append(req.Headers[kHeader], v)
				}
			}
		}
		for kParam, vParam := range r.URL.Query() {
			req.URLParams[kParam] = []string{}
			for _, v := range vParam {
				req.URLParams[kParam] = append(req.URLParams[kParam], v)
			}
		}
		p.saveRequest(req)

		upstream.ServeHTTP(w, r)
	})
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

type oneShotDialer struct {
	c  net.Conn
	mu sync.Mutex
}

func (d *oneShotDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		return nil, errors.New("closed on dial")
	}
	c := d.c
	// TODO
	d.c = nil
	return c, nil
}

type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed on accept")
	}
	c := l.c
	// TODO
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}

func certificateLookupByName(name string) (*tls.Certificate, error) {
	cert, key, err := CreateKeyPair(name)
	if err != nil {
		return nil, err
	}

	var tlsCert tls.Certificate
	if tlsCert, err = tls.LoadX509KeyPair(cert, key); err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func (p *Proxy) http(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	req := model.RequestToSave{
		Host:     r.Host,
		Url:     r.URL.Path,
		Headers: map[string][]string{},
		URLParams: map[string][]string{},
		Body:    "",
		Proto:    "http",
		Method: r.Method,
	}
	// Считать заголовки и тело запроса
	bodyByte, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("cannot read body " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}
	req.Body = string(bodyByte)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyByte))
	for kHeader, vHeader := range r.Header {
		if kHeader != "Proxy-Connection" {
			req.Headers[kHeader] = []string{}
			for _, v := range vHeader {
				req.Headers[kHeader] = append(req.Headers[kHeader], v)
			}
		}
	}
	for kParam, vParam := range r.URL.Query() {
		req.URLParams[kParam] = []string{}
		for _, v := range vParam {
			req.URLParams[kParam] = append(req.URLParams[kParam], v)
		}
	}
	p.saveRequest(req)

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Копировать ответ в ответ для клиента
	for kHeader, vHeader := range resp.Header {
		for _, v := range vHeader {
			w.Header().Add(kHeader, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) newProxiedRequest(w http.ResponseWriter, r *http.Request) *ProxiedRequest {
	return &ProxiedRequest{
		ResponseWriter: w,
		Request:        r,
	}
}

func (p *Proxy) saveRequest(request model.RequestToSave) {
	headers, err := json.Marshal(request.Headers)
	if err != nil{
		log.Println(err)
		return
	}
	params, err := json.Marshal(request.URLParams)
	if err != nil{
		log.Println(err)
		return
	}

	_, err = p.db.Exec("insert into requests (host, url, headers, body, proto, method, params) values ($1, $2, $3," +
		" $4, $5, $6, $7)",
		request.Host, request.Url, headers, request.Body, request.Proto, request.Method, params)
	if err != nil{
		println(err)
	}
}