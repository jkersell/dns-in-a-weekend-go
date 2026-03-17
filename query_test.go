package query

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestDNSHeaderToBytes(t *testing.T) {
	expected := []byte("\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
	h := DNSHeader{
		id:              0x1314,
		flags:           0,
		num_questions:   1,
		num_additionals: 0,
		num_authorities: 0,
		num_answers:     0,
	}

	actual, err := h.ToBytes()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestDNSQuestionsToBytes(t *testing.T) {
	expected := [] byte(
		"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x01\x00\x01",
	)
	h := DNSQuestion{
		name: []byte("example.com"),
		type_: 1,
		class: 1,
	}

	actual, err := h.ToBytes()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
