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
	recordType RRType,
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

// lookupDomain sends a query to the name server at address to request records of type
// recordType for domain and returns a DNSPacket.
func lookupDomain(address, domain string, recordType RRType) (*DNSPacket, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(address, "53"))
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to %v", address)
	}
	defer conn.Close()

	q, err := BuildQuery(dnsQueryID(), domain, recordType)
	if err != nil {
		return nil, fmt.Errorf("Failed to build a DNS query: %v", err)
	}

	conn.Write(q)

	r := bufio.NewReader(conn)
	buf := make([]byte, 1024)
	r.Read(buf)

	packet, err := ParsePacket(buf)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse DNS packet: %v", err)
	}

	return packet, nil
}

func dnsQueryID() uint16 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint16(r.Intn(65535))
}

func main() {
	packet, err := lookupDomain("8.8.8.8", "www.example.com", TYPE_A)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to look up domain: %v\n", err)
		os.Exit(1)
	}

	if packet.header.num_answers == 0 {
		fmt.Println("Domain name not found")
	}

	fmt.Printf("IP: %s\n", dottedDecimal(packet.answers[0].data))
}
