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
	"math/rand"
	"net"
	"os"
	"time"
)

func BuildQuery(
	queryID uint16,
	domainName string,
	recordType DNSQueryType,
) ([]byte, error) {
	header := DNSHeader{
		id:              queryID,
		flags:           RECURSION_DESIRED,
		num_questions:   1,
		num_answers:     0,
		num_authorities: 0,
		num_additionals: 0,
	}
	question := DNSQuestion{
		name:  []byte(domainName),
		type_: recordType,
		class: CLASS_IN,
	}
	var query []byte
	header_bytes, err := header.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("Failed to build query: %v", err)
	}
	query = append(query, header_bytes...)
	question_bytes, err := question.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("Failed to build query: %v", err)
	}
	query = append(query, question_bytes...)
	return query, nil
}

func lookupDomain(domain string) (string, error) {
	address := "8.8.8.8:53"
	conn, err := net.Dial("udp", address)
	if err != nil {
		return "", fmt.Errorf("Failed to connect to %v", address)
	}
	defer conn.Close()

	q, err := BuildQuery(dnsQueryID(), domain, TYPE_A)
	if err != nil {
		return "", fmt.Errorf("Failed to build a DNS query: %v", err)
	}

	conn.Write(q)

	r := bufio.NewReader(conn)
	buf := make([]byte, 1024)
	r.Read(buf)

	packet, err := ParsePacket(buf)
	if err != nil {
		return "", fmt.Errorf("Failed to parse DNS packet: %v", err)
	}

	ipAddress := packet.answers[0].data
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		ipAddress[0],
		ipAddress[1],
		ipAddress[2],
		ipAddress[3],
	), nil
}

func dnsQueryID() uint16 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint16(r.Intn(65535))
}

func main() {
	ip, err := lookupDomain("www.example.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to look up domain: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("IP: ", ip)
}
