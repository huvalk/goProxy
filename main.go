package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	"log"
	"myProxy/proxy"
	"net/http"
)

func main() {
	//var pemPath string
	//flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
	//var keyPath string
	//flag.StringVar(&keyPath, "key", "server.key", "path to key file")
	var proto string
	flag.StringVar(&proto, "proto", "http", "Proxy protocol (http or https)")
	flag.Parse()
	if proto != "http" && proto != "https" {
		log.Fatal("Protocol must be either http or https")
	}
	db, err := sql.Open("sqlite3", "history.sqlite")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	pr := proxy.NewProxy(db)
	server := &http.Server{
		Addr: ":8081",
		Handler: http.HandlerFunc(pr.HandleProxy),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if proto == "http" {
		log.Fatal(server.ListenAndServe())
	} else {
		//log.Fatal(server.ListenAndServeTLS(pemPath, keyPath))
	}
}
