package proxy

import (
	"bytes"
	"database/sql"
	"encoding/json"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

type RequestToSave struct {
	host string
	url string
	headers URLHeaders
	body string
	proto string
}

type URLHeaders map[string][]string

type Proxy struct {
	db *sql.DB
}

func NewProxy(db *sql.DB) *Proxy {
	return &Proxy{
		db: db,
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
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func (p *Proxy) http(w http.ResponseWriter, r *http.Request) {
	req := RequestToSave{
		host:     r.Host,
		url:     r.URL.Path,
		headers: map[string][]string{},
		body:    "",
		proto:    "http",
	}
	// Считать заголовки и тело запроса
	bodyByte, err := ioutil.ReadAll(r.Body)
	req.body = string(bodyByte)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyByte))
	for kHeader, vHeader := range r.Header {
		if kHeader != "Proxy-Connection" {
			req.headers[kHeader] = []string{}
			for _, v := range vHeader {
				req.headers[kHeader] = append(req.headers[kHeader], v)
			}
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

func (p *Proxy) saveRequest(request RequestToSave) {
	headers, err := json.Marshal(request.headers)
	if err != nil{
		println(err)
	}

	_, err = p.db.Exec("insert into requests (host, url, headers, body, proto) values ($1, $2, $3, $4, $5)",
		request.host, request.url, headers, request.body, request.proto)
	if err != nil{
		println(err)
	}
}