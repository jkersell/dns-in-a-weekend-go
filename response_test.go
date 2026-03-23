package main

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

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
		data:  []byte{0x5d, 0xb8, 0xd8, 0x22},
	}
	r := bytes.NewReader(RESPONSE_BYTES)
	r.Seek(33, io.SeekStart)

	actual, err := ParseRecord(r)

	assert.NoError(t, err)
	assert.Equal(t, expected, *actual)
}

func TestDecodePointer(t *testing.T) {
	tests := []struct {
		length   byte
		nextByte byte
		expected uint16
	}{
		{
			length:   0b1111_1111,
			nextByte: 0b1111_1111,
			expected: 16383,
		},
		{
			length:   0b1100_1111,
			nextByte: 0b1111_1111,
			expected: 4095,
		},
		{
			length:   0b1100_0000,
			nextByte: 0b0000_0000,
			expected: 0,
		},
		{
			length:   0b1100_0000,
			nextByte: 0b1111_1111,
			expected: 255,
		},
		{
			length:   0b1100_0000,
			nextByte: 0b0000_0001,
			expected: 1,
		},
	}
	for _, tt := range tests {
		r := bytes.NewReader([]byte{tt.nextByte})

		actual, err := decodePointer(tt.length, r)

		assert.NoError(t, err)
		assert.Equal(t, tt.expected, actual)
	}
}
