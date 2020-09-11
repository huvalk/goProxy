package proxy

import (
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
	url string
	headers URLHeaders
	body string
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
		//handleTunneling(w, r)
	} else {
		p.http(w, r)
	}
}

func https(w http.ResponseWriter, r *http.Request) {
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
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	req := RequestToSave{
		url:     r.Host,
		headers: map[string][]string{},
		body:    "",
	}
	for kHeader, vHeader := range resp.Header {
		req.headers[kHeader] = []string{}
		for _, v := range vHeader {
			w.Header().Add(kHeader, v)
			req.headers[kHeader] = append(req.headers[kHeader], v)
		}
	}

	bodyByte, err := ioutil.ReadAll(r.Body)
	req.body = string(bodyByte)
	p.saveRequest(req)

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) saveRequest(request RequestToSave) {
	headers, err := json.Marshal(request.headers)
	if err != nil{
		println(err)
	}

	_, err = p.db.Exec("insert into requests (url, headers, body) values ($1, $2, $3)",
		request.url, headers, request.body)
	if err != nil{
		println(err)
	}
}