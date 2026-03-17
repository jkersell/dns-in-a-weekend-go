// Package query provides basic DNS query functionality.
//
// This is a toy implementation of a DNS query based on Julia Evens' tutorial [DNS in a
// Weekend]. It provides types to build the
// query header and question, as well as methods to encode them for sending over the
// wire.
//
// [DNS in a Weekend]: https://implement-dns.wizardzines.com
package query

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
	type_ uint16
	class uint16
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
