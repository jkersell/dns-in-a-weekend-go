package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDNSHeaderToBytes(t *testing.T) {
	var tests = []struct {
		h        DNSHeader
		expected []byte
	}{
		{
			h: DNSHeader{
				id:              0x1314,
				flags:           0,
				num_questions:   1,
				num_additionals: 0,
				num_authorities: 0,
				num_answers:     0,
			},
			expected: []byte("\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
		}, {
			h: DNSHeader{
				id:              0x1f2a,
				flags:           1,
				num_questions:   0,
				num_additionals: 1,
				num_authorities: 1,
				num_answers:     1,
			},
			expected: []byte("\x1f\x2a\x00\x01\x00\x00\x00\x01\x00\x01\x00\x01"),
		},
	}

	for _, tt := range tests {
		actual, err := tt.h.ToBytes()

		assert.NoError(t, err)
		assert.Equal(t, tt.expected, actual)
	}
}

func TestDNSQuestionsToBytes(t *testing.T) {
	var tests = []struct {
		q        DNSQuestion
		expected []byte
	}{
		{
			q: DNSQuestion{
				name:  []byte("example.com"),
				type_: 1,
				class: 1,
			},
			expected: []byte(
				"\x07example\x03com\x00\x00\x01\x00\x01",
			),
		}, {
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
		actual, err := tt.q.ToBytes()

		assert.NoError(t, err)
		assert.Equal(t, tt.expected, actual)
	}
}

func TestBuildQuery(t *testing.T) {
	var tests = []struct {
		queryID    uint16
		domainName string
		recordType DNSQueryType
		expected   []byte
	}{
		{
			queryID:    0x3c5f,
			domainName: "www.example.com",
			recordType: TYPE_A,
			expected: []byte(
				"\x3c\x5f\x01\x00\x00\x01\x00\x00" +
					"\x00\x00\x00\x00\x03\x77\x77\x77" +
					"\x07\x65\x78\x61\x6d\x70\x6c\x65" +
					"\x03\x63\x6f\x6d\x00\x00\x01\x00" +
					"\x01",
			),
		},
	}

	for _, tt := range tests {
		actual, err := BuildQuery(tt.queryID, tt.domainName, tt.recordType)

		assert.NoError(t, err)
		assert.Equal(t, tt.expected, actual)
	}
}
