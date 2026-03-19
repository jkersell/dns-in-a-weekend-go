// Package main provides a command to demonstrate basic DNS functionality.
//
// This is a toy implementation of a DNS query based on Julia Evens' tutorial [DNS in a
// Weekend]. It provides types to build the query header and question, as well as
// methods to encode them for sending over the wire.
//
// [DNS in a Weekend]: https://implement-dns.wizardzines.com
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	address := "8.8.8.8:53"
	conn, err := net.Dial("udp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to %v", address)
		os.Exit(1)
	}
	defer conn.Close()

	q, err := BuildQuery(DnsQueryID(), "www.example.com", TYPE_A)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build a DNS query: %v", err)
		os.Exit(1)
	}

	conn.Write(q)
	r := bufio.NewReader(conn)
	buf := make([]byte, 1024)

	r.Read(buf)
}
