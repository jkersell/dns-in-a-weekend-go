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

func Resolve(domainName string, recordType RRType) ([]byte, error) {
	nameserver := "198.41.0.4"
	for {
		fmt.Printf("Querying %s for %s\n", nameserver, domainName)

		packet, err := lookupDomain(nameserver, domainName, recordType)
		if err != nil {
			return nil, fmt.Errorf("Failed to resolve domain: %v\n", err)
		}

		if ip := packet.Answer(); ip != nil {
			return ip, nil
		} else if nsIP := packet.NameserverIP(); nsIP != nil {
			nameserver = string(nsIP)
		} else if nsDomain := packet.Nameserver(); nsDomain != nil {
			ns, err := Resolve(string(nsDomain), recordType)
			if err != nil {
				return nil, fmt.Errorf("Failed to resolve domain: %v\n", err)
			}
			nameserver = string(ns)
		} else {
			return nil, fmt.Errorf("Failed to resolve domain: %v\n", err)
		}
	}
}

func BuildQuery(
	queryID uint16,
	domainName string,
	recordType RRType,
) ([]byte, error) {
	header := DNSHeader{
		id:              queryID,
		flags:           0,
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
	ip, err := Resolve("www.twitter.com", TYPE_A)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve domain: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("IP: %s\n", ip)
}
