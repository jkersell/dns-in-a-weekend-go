package main

import (
	"bytes"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RECURSION_DESIRED is the DNS query header flag to enable recursive queries
const RECURSION_DESIRED = 1 << 8

var RESPONSE_BYTES []byte = []byte{
	0x60, 0x56, 0x81, 0x80,
	0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	0x03, 0x77, 0x77, 0x77,
	0x07, 0x65, 0x78, 0x61,
	0x6d, 0x70, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00, 0x00, 0x01, 0x00,
	0x01, 0xc0, 0x0c, 0x00,
	0x01, 0x00, 0x01, 0x00,
	0x00, 0x52, 0x9b, 0x00,
	0x04, 0x5d, 0xb8, 0xd8,
	0x22,
}

func TestDNSHeaderToBytes(t *testing.T) {
	var tests = []struct {
		name     string
		h        DNSHeader
		expected []byte
	}{
		{
			name: "query",
			h: DNSHeader{
				id:              0x1314,
				flags:           0,
				num_questions:   1,
				num_additionals: 0,
				num_authorities: 0,
				num_answers:     0,
			},
			expected: []byte{
				0x13, 0x14, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		}, {
			name: "response",
			h: DNSHeader{
				id:              0x1f2a,
				flags:           1,
				num_questions:   0,
				num_additionals: 1,
				num_authorities: 1,
				num_answers:     1,
			},
			expected: []byte{
				0x1f, 0x2a, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x01, 0x00, 0x01,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(b *testing.T) {
			actual, err := tt.h.ToBytes()

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestDNSQuestionsToBytes(t *testing.T) {
	var tests = []struct {
		name     string
		q        DNSQuestion
		expected []byte
	}{
		{
			name: "example.com",
			q: DNSQuestion{
				name:  []byte("example.com"),
				type_: 1,
				class: 1,
			},
			expected: []byte(
				"\x07example\x03com\x00\x00\x01\x00\x01",
			),
		}, {
			name: "google.com",
			q: DNSQuestion{
				name:  []byte("google.com"),
				type_: 0,
				class: 0,
			},
			expected: []byte(
				"\x06google\x03com\x00\x00\x00\x00\x00",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := tt.q.ToBytes()

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestParseHeader(t *testing.T) {
	expected := DNSHeader{
		id:              0x6056,
		flags:           33152,
		num_questions:   1,
		num_additionals: 0,
		num_authorities: 0,
		num_answers:     1,
	}
	r := bytes.NewReader(RESPONSE_BYTES)
	r.Seek(0, io.SeekStart)

	actual, err := ParseHeader(r)

	assert.NoError(t, err)
	assert.Equal(t, expected, *actual)
}

func TestParseQuestion(t *testing.T) {
	expected := DNSQuestion{
		name:  []byte("www.example.com"),
		type_: TYPE_A,
		class: CLASS_IN,
	}
	r := bytes.NewReader(RESPONSE_BYTES)
	r.Seek(12, io.SeekStart)

	actual, err := ParseQuestion(r)

	assert.NoError(t, err)
	assert.Equal(t, expected, *actual)
}

func TestParseRecord(t *testing.T) {
	expected := DNSRecord{
		name:  []byte("www.example.com"),
		type_: TYPE_A,
		class: CLASS_IN,
		ttl:   21147,
		data:  []byte("93.184.216.34"),
	}
	r := bytes.NewReader(RESPONSE_BYTES)
	r.Seek(33, io.SeekStart)

	actual, err := ParseRecord(r)

	assert.NoError(t, err)
	assert.Equal(t, expected, *actual)
}

func TestReadData(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		recordType RRType
		dataLen    uint16
		expected   []byte
	}{
		{
			name:       "NS record",
			data:       []byte("\x01e\x0cgtld-servers\x03net"),
			recordType: TYPE_NS,
			dataLen:    18,
			expected:   []byte("e.gtld-servers.net"),
		}, {
			name:       "A record",
			data:       []byte{0x08, 0x08, 0x08, 0x08},
			recordType: TYPE_A,
			dataLen:    4,
			expected:   []byte("8.8.8.8"),
		}, {
			name:       "Unknown record type",
			data:       []byte("return the raw data"),
			recordType: math.MaxUint16,
			dataLen:    19,
			expected:   []byte("return the raw data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := readData(bytes.NewReader(tt.data), tt.recordType, tt.dataLen)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestDecodePointer(t *testing.T) {
	tests := []struct {
		name     string
		length   byte
		nextByte byte
		expected uint16
	}{
		{
			name:     "max value",
			length:   0b1111_1111,
			nextByte: 0b1111_1111,
			expected: 16383,
		},
		{
			name:     "larger value",
			length:   0b1100_1111,
			nextByte: 0b1111_1111,
			expected: 4095,
		},
		{
			name:     "min value",
			length:   0b1100_0000,
			nextByte: 0b0000_0000,
			expected: 0,
		},
		{
			name:     "max next byte",
			length:   0b1100_0000,
			nextByte: 0b1111_1111,
			expected: 255,
		},
		{
			name:     "low value",
			length:   0b1100_0000,
			nextByte: 0b0000_0001,
			expected: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader([]byte{tt.nextByte})

			actual, err := decodePointer(tt.length, r)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestParsePacket(t *testing.T) {
	expected := DNSPacket{
		header: &DNSHeader{
			id:              0x6056,
			flags:           33152,
			num_questions:   1,
			num_additionals: 0,
			num_authorities: 0,
			num_answers:     1,
		},
		questions: []*DNSQuestion{
			{
				name:  []byte("www.example.com"),
				type_: TYPE_A,
				class: CLASS_IN,
			},
		},
		answers: []*DNSRecord{
			{
				name:  []byte("www.example.com"),
				type_: TYPE_A,
				class: CLASS_IN,
				ttl:   21147,
				data:  []byte("93.184.216.34"),
			},
		},
		authorities: []*DNSRecord{},
		additionals: []*DNSRecord{},
	}
	actual, err := ParsePacket(RESPONSE_BYTES)

	assert.NoError(t, err)
	assert.Equal(t, expected, *actual)
}

func TestBuildQuery(t *testing.T) {
	var tests = []struct {
		name       string
		queryID    uint16
		domainName string
		recordType RRType
		flags      uint16
		expected   []byte
	}{
		{
			name:       "example.com recursive",
			queryID:    0x3c5f,
			domainName: "www.example.com",
			recordType: TYPE_A,
			flags:      RECURSION_DESIRED,
			expected: []byte{
				0x3c, 0x5f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
				0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
				0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
				0x01,
			},
		}, {
			name:       "example.com non-recursive",
			queryID:    0x3c5f,
			domainName: "www.example.com",
			recordType: TYPE_A,
			flags:      0,
			expected: []byte{
				0x3c, 0x5f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
				0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
				0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
				0x01,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := BuildQuery(
				tt.queryID,
				tt.domainName,
				tt.recordType,
				tt.flags,
			)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
