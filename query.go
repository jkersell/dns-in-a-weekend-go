// Package query provides basic DNS query functionality.
//
// This is a toy implementation of a DNS query based on Julia Evens' tutorial [DNS in a
// Weekend]. It provides types to build the query header and question, as well as
// methods to encode them for sending over the wire.
//
// The primary interface to this package is the BuildQuery function, which assembles
// a DNSHeader and a DNSQuestion to create a query. A DNSHeader and DNSQuestion can
// be constructed directly and their bytes representation concatenated to create a query.
//
// [DNS in a Weekend]: https://implement-dns.wizardzines.com
package query

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

type DNSQueryType uint16

// TYPE_A is one of many DNS query types, however, it is the only one currently needed
// for this project.
const TYPE_A DNSQueryType = 1

type DNSQueryClass uint16

// CLASS_IN is one of many DNS query classes, however, it is the only one currently
// needed for this project.
const CLASS_IN DNSQueryClass = 1

// RECURSION_DESIRED is the DNS query header flag to enable recursive queries
const RECURSION_DESIRED = 1 << 8

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

func DnsQueryID() uint16 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint16(r.Intn(65535))
}

// DNSHeader is a representation of the header of a DNS query.
type DNSHeader struct {
	id              uint16
	flags           uint16
	num_questions   uint16
	num_answers     uint16
	num_authorities uint16
	num_additionals uint16
}

// ToBytes returns a the encoded DNS header as a slice of bytes ready to transmit.
func (h *DNSHeader) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, h.id); err != nil {
		return nil, fmt.Errorf("Failed to encode header: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, h.flags); err != nil {
		return nil, fmt.Errorf("Failed to encode header: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, h.num_questions); err != nil {
		return nil, fmt.Errorf("Failed to encode header: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, h.num_answers); err != nil {
		return nil, fmt.Errorf("Failed to encode header: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, h.num_authorities); err != nil {
		return nil, fmt.Errorf("Failed to encode header: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, h.num_additionals); err != nil {
		return nil, fmt.Errorf("Failed to encode header: %v", err)
	}
	return buf.Bytes(), nil
}

// DNSQuestion is a representation of the header of a DNS query.
type DNSQuestion struct {
	name  []byte
	type_ DNSQueryType
	class DNSQueryClass
}

// ToBytes returns a the encoded DNS question as a slice of bytes ready to transmit.
func (q *DNSQuestion) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, q.encodeName()); err != nil {
		return nil, fmt.Errorf("Failed to encode question: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, q.type_); err != nil {
		return nil, fmt.Errorf("Failed to encode question: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, q.class); err != nil {
		return nil, fmt.Errorf("Failed to encode question: %v", err)
	}
	return buf.Bytes(), nil
}

// encodeName returns a slice of bytes containing the name encoded as a series of labels
// consisting of a length octet, followed by that many octets, and terminated with a null
// octet.
func (q *DNSQuestion) encodeName() []byte {
	encoded := []byte{}
	parts := bytes.Split(q.name, []byte("."))
	for _, part := range parts {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, part...)
	}
	encoded = append(encoded, 0x00)
	return encoded
}
