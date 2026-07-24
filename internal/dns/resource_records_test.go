package dns

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceRecordEncode_Basic(t *testing.T) {
	tests := []struct {
		name   string
		record ResourceRecord
		want   []byte
	}{
		{
			"root A IN with 4-byte RDATA",
			ResourceRecord{Name: "", Type: A, Class: IN, TTL: 300, RDLENGTH: 4, RDATA: []byte{0x5D, 0xB8, 0xD8, 0x22}},
			[]byte{
				0x00,       // NAME = root
				0x00, 0x01, // TYPE = A
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x01, 0x2C, // TTL = 300
				0x00, 0x04, // RDLENGTH = 4
				0x5D, 0xB8, 0xD8, 0x22, // RDATA (93.184.216.34)
			},
		},
		{
			"www.example.com A IN",
			ResourceRecord{Name: "www.example.com", Type: A, Class: IN, TTL: 300, RDLENGTH: 4, RDATA: []byte{0x5D, 0xB8, 0xD8, 0x22}},
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, // TYPE = A
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x01, 0x2C, // TTL = 300
				0x00, 0x04, // RDLENGTH = 4
				0x5D, 0xB8, 0xD8, 0x22, // RDATA
			},
		},
		{
			"example.com AAAA IN with 16-byte RDATA",
			ResourceRecord{
				Name:     "example.com",
				Type:     AAAA,
				Class:    IN,
				TTL:      3600,
				RDLENGTH: 16,
				RDATA:    []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
			},
			[]byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x1C, // TYPE = AAAA (28)
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x0E, 0x10, // TTL = 3600
				0x00, 0x10, // RDLENGTH = 16
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // RDATA
			},
		},
		{
			"max TTL, type and class",
			ResourceRecord{Name: "com", Type: 0xFFFF, Class: 0xFFFF, TTL: 0xFFFFFFFF, RDLENGTH: 2, RDATA: []byte{0xAA, 0xBB}},
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0xFF, 0xFF, // TYPE
				0xFF, 0xFF, // CLASS
				0xFF, 0xFF, 0xFF, 0xFF, // TTL
				0x00, 0x02, // RDLENGTH = 2
				0xAA, 0xBB, // RDATA
			},
		},
		{
			"empty RDATA encodes RDLENGTH zero",
			ResourceRecord{Name: "com", Type: NS, Class: IN, TTL: 0, RDLENGTH: 0, RDATA: []byte{}},
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x02, // TYPE = NS
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x00, 0x00, // TTL = 0
				0x00, 0x00, // RDLENGTH = 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.record.Encode()
			assert.NoError(t, err, "Encode should not fail for valid record")
			assert.Equal(t, tt.want, got, "Encode should produce expected wire bytes")
		})
	}
}

func TestResourceRecordEncode_NameErrors(t *testing.T) {
	tests := []struct {
		name    string
		record  ResourceRecord
		wantErr error
	}{
		{"empty label in name", ResourceRecord{Name: "a..b", Type: A, Class: IN, RDATA: []byte{1, 2, 3, 4}}, ErrEmptyLabel},
		{"label over 63 bytes", ResourceRecord{Name: string(make([]byte, 64)), Type: A, Class: IN, RDATA: []byte{1, 2, 3, 4}}, ErrLabelTooLong},
		{"name over 255 bytes", ResourceRecord{Name: repeatLabel("aaaa", 64), Type: A, Class: IN, RDATA: []byte{1, 2, 3, 4}}, ErrNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.record.Encode()
			assert.Error(t, err, "Encode should fail for malformed name")
			assert.True(t, errors.Is(err, tt.wantErr),
				"Encode error = %v, want %v", err, tt.wantErr)
		})
	}
}

func TestResourceRecordDecode_Basic(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		offset int
		want   ResourceRecord
		wantN  int
	}{
		{
			"root A IN",
			[]byte{
				0x00,       // NAME = root
				0x00, 0x01, // TYPE = A
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x01, 0x2C, // TTL = 300
				0x00, 0x04, // RDLENGTH = 4
				0x5D, 0xB8, 0xD8, 0x22, // RDATA
			},
			0,
			ResourceRecord{Name: "", Type: A, Class: IN, TTL: 300, RDLENGTH: 4, RDATA: []byte{0x5D, 0xB8, 0xD8, 0x22}},
			15,
		},
		{
			"www.example.com A IN",
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, // TYPE = A
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x01, 0x2C, // TTL = 300
				0x00, 0x04, // RDLENGTH = 4
				0x5D, 0xB8, 0xD8, 0x22, // RDATA
			},
			0,
			ResourceRecord{Name: "www.example.com", Type: A, Class: IN, TTL: 300, RDLENGTH: 4, RDATA: []byte{0x5D, 0xB8, 0xD8, 0x22}},
			31,
		},
		{
			"max TTL, type and class",
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0xFF, 0xFF, // TYPE
				0xFF, 0xFF, // CLASS
				0xFF, 0xFF, 0xFF, 0xFF, // TTL
				0x00, 0x02, // RDLENGTH = 2
				0xAA, 0xBB, // RDATA
			},
			0,
			ResourceRecord{Name: "com", Type: 0xFFFF, Class: 0xFFFF, TTL: 0xFFFFFFFF, RDLENGTH: 2, RDATA: []byte{0xAA, 0xBB}},
			17,
		},
		{
			"empty RDATA",
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x02, // TYPE = NS
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x00, 0x00, // TTL = 0
				0x00, 0x00, // RDLENGTH = 0
			},
			0,
			ResourceRecord{Name: "com", Type: NS, Class: IN, TTL: 0, RDLENGTH: 0, RDATA: []byte{}},
			15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ResourceRecord
			n, err := got.Decode(tt.data, tt.offset)
			assert.NoError(t, err, "Decode should not fail for valid data")
			assert.Equal(t, tt.want, got, "Decode should produce expected record")
			assert.Equal(t, tt.wantN, n, "Decode should return the offset just past the record")
		})
	}
}

func TestResourceRecordDecode_Compression(t *testing.T) {
	// A record at offset 13 whose NAME is a compression pointer (C0 00)
	// back to the "example.com" name at offset 0. Decode should resolve
	// the full name and return the offset just past the RDATA.
	data := []byte{
		// offset 0: "example.com"
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		// offset 13: resource record
		0xC0, 0x00, // NAME = pointer to offset 0
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x01, 0x2C, // TTL = 300
		0x00, 0x04, // RDLENGTH = 4
		0x5D, 0xB8, 0xD8, 0x22, // RDATA
	}

	var got ResourceRecord
	n, err := got.Decode(data, 13)
	assert.NoError(t, err, "Decode should follow compression pointers")
	assert.Equal(t, "example.com", got.Name, "Decode should resolve the compressed name")
	assert.Equal(t, A, got.Type)
	assert.Equal(t, IN, got.Class)
	assert.Equal(t, uint32(300), got.TTL)
	assert.Equal(t, []byte{0x5D, 0xB8, 0xD8, 0x22}, got.RDATA)
	assert.Equal(t, 29, n, "Decode should return the offset just past the RDATA")
}

func TestResourceRecordDecode_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		offset  int
		wantErr error
	}{
		{
			"empty slice",
			[]byte{},
			0,
			ErrNameTruncated,
		},
		{
			// Name decodes (5 bytes), but only 2 bytes remain — not enough
			// for TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10.
			"truncated fixed fields",
			[]byte{0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01},
			0,
			ErrResourceRecordTooShort,
		},
		{
			// Fixed fields present and RDLENGTH = 4, but only 2 RDATA bytes
			// follow — not enough to satisfy RDLENGTH.
			"RDLENGTH exceeds remaining",
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x01, // TYPE
				0x00, 0x01, // CLASS
				0x00, 0x00, 0x01, 0x2C, // TTL
				0x00, 0x04, // RDLENGTH = 4
				0x5D, 0xB8, // only 2 RDATA bytes
			},
			0,
			ErrRdataTruncated,
		},
		{
			"self-loop pointer in name",
			[]byte{0xC0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			0,
			ErrInvalidPointer,
		},
		{
			"truncated name",
			[]byte{0x03, 'c'},
			0,
			ErrNameTruncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ResourceRecord
			_, err := got.Decode(tt.data, tt.offset)
			assert.Error(t, err, "Decode should return error for malformed data")
			assert.True(t, errors.Is(err, tt.wantErr),
				"Decode error = %v, want %v", err, tt.wantErr)
		})
	}
}

func TestResourceRecordRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		record ResourceRecord
	}{
		{"root A IN", ResourceRecord{Name: "", Type: A, Class: IN, TTL: 300, RDLENGTH: 4, RDATA: []byte{0x5D, 0xB8, 0xD8, 0x22}}},
		{"www.example.com A IN", ResourceRecord{Name: "www.example.com", Type: A, Class: IN, TTL: 300, RDLENGTH: 4, RDATA: []byte{0x5D, 0xB8, 0xD8, 0x22}}},
		{"example.com AAAA IN", ResourceRecord{Name: "example.com", Type: AAAA, Class: IN, TTL: 3600, RDLENGTH: 16, RDATA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}}},
		{"example.com MX IN", ResourceRecord{Name: "example.com", Type: MX, Class: IN, TTL: 600, RDLENGTH: 7, RDATA: []byte{0x00, 0x0A, 0x03, 'm', 'a', 'i', 0x00}}},
		{"max TTL, type and class", ResourceRecord{Name: "com", Type: 0xFFFF, Class: 0xFFFF, TTL: 0xFFFFFFFF, RDLENGTH: 2, RDATA: []byte{0xAA, 0xBB}}},
		{"empty RDATA", ResourceRecord{Name: "com", Type: NS, Class: IN, TTL: 0, RDLENGTH: 0, RDATA: []byte{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.record.Encode()
			assert.NoError(t, err, "Encode should not fail")

			var decoded ResourceRecord
			n, err := decoded.Decode(wire, 0)
			assert.NoError(t, err, "Decode should not fail on encoded data")
			assert.Equal(t, len(wire), n, "Decode offset should match Encode length")
			assert.Equal(t, tt.record, decoded, "round trip Encode → Decode should preserve all fields")
		})
	}
}
