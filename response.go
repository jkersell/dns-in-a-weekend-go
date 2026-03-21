package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ParseHeader parses the header from a DNS response and returns it in a DNSHeader
func ParseHeader(r *bytes.Reader) (*DNSHeader, error) {
	var h DNSHeader
	err := binary.Read(r, binary.BigEndian, &h.id)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the header: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &h.flags)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the header: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &h.num_questions)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the header: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &h.num_answers)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the header: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &h.num_authorities)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the header: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &h.num_additionals)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the header: %v", err)
	}
	return &h, nil
}

// ParseQuestion parses a DNS question from a DNS response and returns it in a
// DNSQuestion
func ParseQuestion(r *bytes.Reader) (*DNSQuestion, error) {
	var q DNSQuestion
	name, err := decodeName(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the question: %v", err)
	}
	q.name = name
	err = binary.Read(r, binary.BigEndian, &q.type_)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the question: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &q.class)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the question: %v", err)
	}
	return &q, nil
}

// decodeName decodes the name in a DNS question and returns it as a slice of bytes.
// This implementation does not handle compression.
func decodeName(r *bytes.Reader) ([]byte, error) {
	var parts [][]byte
	for length, err := r.ReadByte(); length != 0; length, err = r.ReadByte() {
		if err != nil {
			return nil, fmt.Errorf("Failed to decode name: %v", err)
		}

		part := make([]byte, length)
		io.ReadFull(r, part)
		parts = append(parts, part)
	}
	return bytes.Join(parts, []byte(".")), nil
}
