package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// DNSRecord is a representation of a DNS record
type DNSRecord struct {
	name  []byte
	type_ DNSQueryType
	class DNSQueryClass
	ttl   uint32
	data  []byte
}

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
func decodeName(r *bytes.Reader) ([]byte, error) {
	var parts [][]byte
	for length, err := r.ReadByte(); length != 0; length, err = r.ReadByte() {
		if err != nil {
			return nil, fmt.Errorf("Failed to decode name: %v", err)
		}

		if length&0b1100_0000 != 0 {
			name, err := decodeCompressedName(length, r)
			if err != nil {
				return nil, fmt.Errorf("Failed to decode name: %v", err)
			}
			parts = append(parts, name)
			break
		} else {
			part := make([]byte, length)
			io.ReadFull(r, part)
			parts = append(parts, part)
		}
	}
	return bytes.Join(parts, []byte(".")), nil
}

// decodeCompressedName decodes a domain name from a DNS reponse that has been
// compressed using the compression algorithm described in RFC 1035. If the first
// two bits of the field length are 11, then it contains a pointer to the domain
// name elsewhere in the response. In that case, the remaining 6 bits of the field
// are combinted with the following byte to form a pointer to the domain name.
func decodeCompressedName(length byte, r *bytes.Reader) ([]byte, error) {
	pointer, err := decodePointer(length, r)

	currentPos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode compressed name: %v", err)
	}

	_, err = r.Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf(
			"Failed to decode compressed name: Could not seek to name: %v", err,
		)
	}

	result, err := decodeName(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode compressed name: %v", err)
	}

	_, err = r.Seek(currentPos, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode compressed name: %v", err)
	}

	return result, nil
}

// decodePointer decodes a pointer to a domain name as described in the compression
// section of RFC 1035. If the first two bits of the field length are 11, then it
// contains a pointer to the domain name elsewhere in the response. In that case,
// the remaining 6 bits of the field are combinted with the following byte to form
// a pointer to the domain name.
func decodePointer(length byte, r *bytes.Reader) (uint16, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("Failed to decode name pointer: %v", err)
	}

	pointerBytes := []byte{byte(length & 0b0011_1111), b}

	var pointer uint16
	_, err = binary.Decode(pointerBytes, binary.BigEndian, &pointer)
	if err != nil {
		return 0, fmt.Errorf("Failed to decode name pointer: %v", err)
	}
	return pointer, nil
}

// ParseRecord parses a DNS record from a DNS response and returns it in a
// DNSRecord
func ParseRecord(r *bytes.Reader) (*DNSRecord, error) {
	var rec DNSRecord
	name, err := decodeName(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record: %v", err)
	}

	rec.name = name
	err = binary.Read(r, binary.BigEndian, &rec.type_)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record: %v", err)
	}

	err = binary.Read(r, binary.BigEndian, &rec.class)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record: %v", err)
	}

	err = binary.Read(r, binary.BigEndian, &rec.ttl)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record: %v", err)
	}

	var dataLen uint16
	err = binary.Read(r, binary.BigEndian, &dataLen)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record: %v", err)
	}

	rec.data = make([]byte, dataLen)
	err = binary.Read(r, binary.BigEndian, &rec.data)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record reading data: %v", err)
	}

	return &rec, nil
}
