package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"myProxy/proxy"
	"myProxy/requester"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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

	_, err = db.Exec(`create table IF NOT EXISTS requests 
	(
		url int,
		headers int,
		body int,
		id INTEGER not null
	primary key autoincrement,
		host text default '',
	proto text default '',
	method TEXT default '',
	params TEXT default ''
	);`)
	if err != nil {
		log.Fatal(err)
	}

	pr := proxy.NewProxy(db)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		errHttp := http.ListenAndServe(fmt.Sprintf(":%d", 8081), http.HandlerFunc(pr.HandleProxy))
		if errHttp != nil {
			log.Fatal("Web server (HTTP): ", errHttp)
		}
	}()

	requesterInst := requester.NewRequester(db)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("-> ")
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)

		repeat := "repeat "
		xss := "xss "
		if pos := strings.Index(text, repeat); pos == 0 {
			text = text[len(repeat):]
			id, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				fmt.Println("Parse id error")
				continue
			}

			if requesterInst.RepeatRequest(id) != nil {
				fmt.Println("Parse id error")
			}
		} else if pos := strings.Index(text, xss); pos == 0 {
			text = text[len(xss):]
			id, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				fmt.Println("Parse id error")
				continue
			}

			if vuln, mbVuln, err := requesterInst.XSSRequest(id); err != nil {
				fmt.Println("Parse id error")
			} else {
				if vuln != nil {
					fmt.Println("Vulnerable are ", vuln)
				}
				if mbVuln != nil {
					fmt.Println("May be vulnerable are ", mbVuln)
				}
			}

			fmt.Println("Done")
		} else {
			continue
		}
	}

	wg.Wait()
}
