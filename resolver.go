package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type RRType uint16
type RRClass uint16

const TYPE_A RRType = 1
const TYPE_NS RRType = 2

// CLASS_IN is one of many DNS query classes, however, it is the only one currently
// needed for this project.
const CLASS_IN RRClass = 1

// DNSPacket is a representation of a DNS packet
type DNSPacket struct {
	header      *DNSHeader
	questions   []*DNSQuestion
	answers     []*DNSRecord
	authorities []*DNSRecord
	additionals []*DNSRecord
}

// ParsePacket takes a slice of bytes and attempts to parse a DNS packet from it. If
// successful a DNSPacket is returned.
func ParsePacket(data []byte) (*DNSPacket, error) {
	r := bytes.NewReader(data)
	header, err := ParseHeader(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse a DNS packet: %v", err)
	}

	questions := make([]*DNSQuestion, header.num_questions)
	for i := 0; i < int(header.num_questions); i++ {
		q, err := ParseQuestion(r)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse a DNS packet: %v", err)
		}
		questions[i] = q
	}

	answers := make([]*DNSRecord, header.num_answers)
	for i := 0; i < int(header.num_answers); i++ {
		a, err := ParseRecord(r)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse a DNS packet: %v", err)
		}
		answers[i] = a
	}

	authorities := make([]*DNSRecord, header.num_authorities)
	for i := 0; i < int(header.num_authorities); i++ {
		auth, err := ParseRecord(r)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse a DNS packet: %v", err)
		}
		authorities[i] = auth
	}

	additionals := make([]*DNSRecord, header.num_additionals)
	for i := 0; i < int(header.num_additionals); i++ {
		ad, err := ParseRecord(r)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse a DNS packet: %v", err)
		}
		additionals[i] = ad
	}

	return &DNSPacket{
		header:      header,
		questions:   questions,
		answers:     answers,
		authorities: authorities,
		additionals: additionals,
	}, nil
}

// Answer returns the first A record in the answers section
func (p *DNSPacket) Answer() []byte {
	for _, a := range p.answers {
		if a.type_ == TYPE_A {
			return a.data
		}
	}
	return nil
}

// Nameserver returns the first NS record in the authorities section
func (p *DNSPacket) Nameserver() []byte {
	for _, n := range p.authorities {
		if n.type_ == TYPE_NS {
			return n.data
		}
	}
	return nil
}

// NameserverIP returns the first A record in the additionals section
func (p *DNSPacket) NameserverIP() []byte {
	for _, n := range p.additionals {
		if n.type_ == TYPE_A {
			return n.data
		}
	}
	return nil
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

// DNSQuestion is a representation of the header of a DNS query.
type DNSQuestion struct {
	name  []byte
	type_ RRType
	class RRClass
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
	for part := range bytes.SplitSeq(q.name, []byte(".")) {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, part...)
	}
	encoded = append(encoded, 0x00)
	return encoded
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

// DNSRecord is a representation of a DNS record
type DNSRecord struct {
	name  []byte
	type_ RRType
	class RRClass
	ttl   uint32
	data  []byte
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

	rec.data, err = readData(r, rec.type_, dataLen)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record: %v", err)
	}

	return &rec, nil
}

// readData reads dataLen bytes from r and decodes the read data according the the
// the type of the record specified by recordType. The decoded data is returned as a
// byte slice.
func readData(
	r *bytes.Reader,
	recordType RRType,
	dataLen uint16,
) ([]byte, error) {
	if recordType == TYPE_NS {
		name, err := decodeName(r)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse the record: %v", err)
		}
		return name, nil
	}

	raw_data := make([]byte, dataLen)
	err := binary.Read(r, binary.BigEndian, raw_data)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the record while reading data: %v", err)
	}

	if recordType == TYPE_A {
		return dottedDecimal(raw_data), nil
	}
	return raw_data, nil
}

// dottedDecimal reads four bytes from ipAddress and returns a byte slice with
// those bytes pretty printed as decimal numbers separated by dots.
func dottedDecimal(ipAddress []byte) []byte {
	var dotted []byte
	return fmt.Appendf(
		dotted,
		"%d.%d.%d.%d",
		ipAddress[0],
		ipAddress[1],
		ipAddress[2],
		ipAddress[3],
	)
}
