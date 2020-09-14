package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"myProxy/proxy"
	"net/http"
)

func main() {
	var pemPath string
	flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
	var keyPath string
	flag.StringVar(&keyPath, "key", "server.key", "path to key file")
	db, err := sql.Open("sqlite3", "history.sqlite")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	pr := proxy.NewProxy(db)

	go func() {
		errHttp := http.ListenAndServe(fmt.Sprintf(":%d", 8081), http.HandlerFunc(pr.HandleProxy))
		if errHttp != nil {
			log.Fatal("Web server (HTTP): ", errHttp)
		}
	}()

	errHttp := http.ListenAndServeTLS(fmt.Sprintf(":%d", 8082), pemPath, keyPath, http.HandlerFunc(pr.HandleProxy))
	if errHttp != nil {
		log.Fatal("Web server (HTTPS): ", errHttp)
	}
}