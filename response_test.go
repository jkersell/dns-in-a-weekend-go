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
