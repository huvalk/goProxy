package requester

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"myProxy/model"
	"net/http"
	"strings"
	"time"
)

type Requester struct {
	db *sql.DB
	client *http.Client
}

func NewRequester(db *sql.DB) *Requester {
	//caCert, err := ioutil.ReadFile("./ca.crt")
	//if err != nil {
	//	log.Fatalf("Reading server certificate: %s", err)
	//}
	//caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)
	//
	//// Create TLS configuration with the certificate of the server
	//tlsConfig := &tls.Config{
	//	RootCAs: caCertPool,
	//}

	return &Requester{
		db: db,
		client: &http.Client{
			Timeout: 10 * time.Second,
			//Transport: &http.Transport {
			//	: tlsConfig,
			//},
		},
	}
}

func (r *Requester) RepeatRequest(requestId int64) (err error) {
	row := r.db.QueryRow("select host, url, headers, body, proto, method, params from requests where id = $1", requestId)
	if err != nil {
		return err
	}

	request := model.RequestToSave{}
	var headers string
	var params string
	err = row.Scan(&request.Host, &request.Url, &headers, &request.Body, &request.Proto, &request.Method, &params)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(headers), &request.Headers)
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(params), &request.URLParams)
	if err != nil {
		return
	}

	fullURL := request.Proto + "://" + request.Host + request.Url
	req, err := http.NewRequest(request.Method, fullURL, bytes.NewBuffer([]byte(request.Body)))
	if err != nil {
		return err
	}

	for kHeader, vHeader := range request.Headers {
		for _, v := range vHeader {
			req.Header.Add(kHeader, v)
		}
	}
	for kParam, vParam := range request.URLParams {
		req.URL.Query().Set(kParam, vParam[0])
		for i := 1; i < len(vParam); i++ {
			req.URL.Query().Add(kParam, vParam[i])
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}
	bodyByte, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Println("cannot read body " + fullURL)
		return
	}
	log.Printf("Result for request for: %s is %s \n %s", fullURL, resp.Status, string(bodyByte))
	return nil
}

func (r *Requester) XSSRequest(requestId int64) (vuln []string, mbVuln []string, err error) {
	request, err := r.loadRequest(requestId)
	if err != nil {
		return nil, nil, err
	}

	fullURL := request.Proto + "://" + request.Host + request.Url
	randomString := "nkpbrwx96bg7zyu5sw6k"
	XSSString := fmt.Sprintf("vulnerable\\'\"><img src onerror=alert(%s)>", randomString)
	for kSub, _ := range request.URLParams {
		req, err := http.NewRequest(request.Method, fullURL, bytes.NewBuffer([]byte(request.Body)))
		if err != nil {
			return nil, nil, err
		}

		for kHeader, vHeader := range request.Headers {
			for _, v := range vHeader {
				req.Header.Add(kHeader, v)
			}
		}

		q := req.URL.Query()
		for kParam, vParam := range request.URLParams {
			if kSub == kParam {
				q.Add(kParam, XSSString)
			} else {
				for _, val := range vParam {
					q.Add(kParam, val)
				}
			}
		}
		req.URL.RawQuery = q.Encode()

		resp, err := r.client.Do(req)
		if err != nil {
			return nil, nil, err
		}

		bodyByte, err := r.decodeBody(resp)
		if bytes.Contains(bodyByte, []byte(XSSString)) {
			vuln = append(vuln, kSub)
		}
		if bytes.Contains(bodyByte, []byte(randomString)) {
			mbVuln = append(mbVuln, kSub)
		}
	}

	bufBody := request.Body
	posName := 0
	posEq := strings.IndexRune(bufBody, '=')
	posAnd := strings.IndexRune(bufBody, '&')
	for posEq != -1 && (posEq < posAnd || posAnd == -1) {
		bufBody = bufBody[:posEq] + string('-') + bufBody[posEq+1:]
		copyBody := request.Body[:(posEq + 1)]
		copyBody += XSSString
		if posAnd != -1 {
			bufBody = bufBody[:posAnd] + string('-') + bufBody[posAnd+1:]
			copyBody += request.Body[posAnd:]
		}

		req, err := http.NewRequest(request.Method, fullURL, bytes.NewBuffer([]byte(copyBody)))
		if err != nil {
			return nil, nil, err
		}

		for kHeader, vHeader := range request.Headers {
			for _, v := range vHeader {
				req.Header.Add(kHeader, v)
			}
		}
		q := req.URL.Query()
		for kParam, vParam := range request.URLParams {
			for _, val := range vParam {
				q.Add(kParam, val)
			}
		}
		req.URL.RawQuery = q.Encode()

		resp, err := r.client.Do(req)
		if err != nil {
			return nil, nil, err
		}

		bodyByte, err := r.decodeBody(resp)
		if bytes.Contains(bodyByte, []byte(XSSString)) {
			vuln = append(vuln, request.Body[posName:posEq])
		}
		if bytes.Contains(bodyByte, []byte(randomString)) {
			mbVuln = append(mbVuln, request.Body[posName:posEq])
		}
		posName = posAnd + 1
		posEq = strings.IndexRune(bufBody, '=')
		posAnd = strings.IndexRune(bufBody, '&')
	}

	return vuln, mbVuln, nil
}

func (r *Requester) loadRequest(requestId int64) (save model.RequestToSave, err error) {
	row := r.db.QueryRow("select host, url, headers, body, proto, method, params from requests where id = $1",
		requestId)

	var headers string
	var params string
	err = row.Scan(&save.Host, &save.Url, &headers, &save.Body, &save.Proto, &save.Method, &params)
	if err != nil {
		return save, err
	}

	err = json.Unmarshal([]byte(headers), &save.Headers)
	if err != nil {
		return save, err
	}
	err = json.Unmarshal([]byte(params), &save.URLParams)
	if err != nil {
		return save, err
	}

	return save, err
}

func (r *Requester) decodeBody(resp *http.Response) (res []byte, err error) {
	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}

	return ioutil.ReadAll(reader)
}