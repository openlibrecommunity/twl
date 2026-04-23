package main

import (
	"fmt"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

func main() {
	db, err := maxminddb.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer db.Close()

	ip := net.ParseIP("51.250.10.127") // Yandex Cloud IP

	var record map[string]interface{}
	err = db.Lookup(ip, &record)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", record)
}
