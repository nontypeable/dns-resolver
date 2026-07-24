package dns

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNameEncode_Basic(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
	}{
		{"root empty", "", []byte{0x00}},
		{"root dot", ".", []byte{0x00}},
		{"single label", "com", []byte{0x03, 'c', 'o', 'm', 0x00}},
		{
			"two labels", "example.com",
			[]byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
		},
		{
			"three labels", "www.example.com",
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
			},
		},
		{
			"trailing dot normalized to same as without", "www.example.com.",
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeName(tt.in)
			assert.NoError(t, err, "encodeName should not fail for valid name")
			assert.Equal(t, tt.want, got, "encodeName should produce expected wire bytes")
		})
	}
}

func TestNameEncode_Errors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty label in the middle", "a..b", ErrEmptyLabel},
		{"leading empty label", ".www.example.com", ErrEmptyLabel},
		{"label over 63 bytes", "a." + string(make([]byte, 64)) + ".b", ErrLabelTooLong},
		{"name over 255 bytes total", repeatLabel("aaaa", 64), ErrNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeName(tt.in)
			assert.Error(t, err, "encodeName should fail for invalid name")
			assert.True(t, errors.Is(err, tt.wantErr),
				"encodeName error = %v, want %v", err, tt.wantErr)
		})
	}
}

func TestNameDecode_Basic(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		offset int
		want   string
		wantN  int
	}{
		{
			"root terminator", []byte{0x00}, 0, "", 1,
		},
		{
			"single label", []byte{0x03, 'c', 'o', 'm', 0x00}, 0, "com", 5,
		},
		{
			"three labels",
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
			},
			0, "www.example.com", 17,
		},
		{
			// A name at offset 5 uses a compression pointer (C0 00) back to
			// the "com" name at offset 0. decodeName should return the full
			// "example.com" and an offset pointing just past the pointer.
			"compression pointer",
			[]byte{
				0x03, 'c', 'o', 'm', 0x00, // offset 0: "com"
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // offset 5: "example"
				0xC0, 0x00, // offset 13: pointer to offset 0
			},
			5, "example.com", 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n, err := decodeName(tt.data, tt.offset)
			assert.NoError(t, err, "decodeName should not fail for valid name")
			assert.Equal(t, tt.want, got, "decodeName should produce expected dotted name")
			assert.Equal(t, tt.wantN, n, "decodeName should return the offset just past consumed bytes")
		})
	}
}

func TestNameDecode_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		offset  int
		wantErr error
	}{
		{"length byte with no label bytes", []byte{0x03}, 0, ErrNameTruncated},
		{"length byte with partial label", []byte{0x03, 'a'}, 0, ErrNameTruncated},
		{"pointer to itself (self-loop)", []byte{0xC0, 0x00}, 0, ErrInvalidPointer},
		{"pointer beyond data", []byte{0xC0, 0x05}, 0, ErrInvalidPointer},
		{"pointer forward to a later offset", []byte{0x03, 'a', 'b', 'c', 0xC0, 0x05}, 0, ErrInvalidPointer},
		{"truncated pointer (only high byte)", []byte{0xC0}, 0, ErrNameTruncated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeName(tt.data, tt.offset)
			assert.Error(t, err, "decodeName should fail for malformed input")
			assert.True(t, errors.Is(err, tt.wantErr),
				"decodeName error = %v, want %v", err, tt.wantErr)
		})
	}
}

func TestNameRoundTrip(t *testing.T) {
	names := []string{
		"",
		"com",
		"example.com",
		"www.example.com",
		"a.b.c.d.e.f.g.example.com",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			wire, err := encodeName(n)
			assert.NoError(t, err)
			got, n2, err := decodeName(wire, 0)
			assert.NoError(t, err)
			assert.Equal(t, len(wire), n2, "decode offset should match encode length")
			assert.Equal(t, n, got, "round trip encode → decode should preserve the name")
		})
	}
}

func TestQuestionEncode_Basic(t *testing.T) {
	tests := []struct {
		name     string
		question Question
		want     []byte
	}{
		{
			"root A IN",
			Question{Name: "", Type: A, Class: IN},
			[]byte{0x00, 0x00, 0x01, 0x00, 0x01},
		},
		{
			"www.example.com A IN",
			Question{Name: "www.example.com", Type: A, Class: IN},
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, // QTYPE = A
				0x00, 0x01, // QCLASS = IN
			},
		},
		{
			"example.com MX IN",
			Question{Name: "example.com", Type: MX, Class: IN},
			[]byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x0F, // QTYPE = MX
				0x00, 0x01, // QCLASS = IN
			},
		},
		{
			"max type and class",
			Question{Name: "com", Type: 0xFFFF, Class: 0xFFFF},
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0xFF, 0xFF,
				0xFF, 0xFF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.question.Encode()
			assert.NoError(t, err, "Encode should not fail for valid question")
			assert.Equal(t, tt.want, got, "Encode should produce expected wire bytes")
		})
	}
}

func TestQuestionEncode_NameErrors(t *testing.T) {
	tests := []struct {
		name     string
		question Question
		wantErr  error
	}{
		{"empty label in name", Question{Name: "a..b", Type: A, Class: IN}, ErrEmptyLabel},
		{"label over 63 bytes", Question{Name: string(make([]byte, 64)), Type: A, Class: IN}, ErrLabelTooLong},
		{"name over 255 bytes", Question{Name: repeatLabel("aaaa", 64), Type: A, Class: IN}, ErrNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.question.Encode()
			assert.Error(t, err, "Encode should fail for malformed name")
			assert.True(t, errors.Is(err, tt.wantErr),
				"Encode error = %v, want %v", err, tt.wantErr)
		})
	}
}

func TestQuestionDecode_Basic(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		want  Question
		wantN int
	}{
		{
			"root A IN",
			[]byte{0x00, 0x00, 0x01, 0x00, 0x01},
			Question{Name: "", Type: A, Class: IN},
			5,
		},
		{
			"www.example.com A IN",
			[]byte{
				0x03, 'w', 'w', 'w',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01,
				0x00, 0x01,
			},
			Question{Name: "www.example.com", Type: A, Class: IN},
			21,
		},
		{
			"max type and class",
			[]byte{
				0x03, 'c', 'o', 'm', 0x00,
				0xFF, 0xFF,
				0xFF, 0xFF,
			},
			Question{Name: "com", Type: 0xFFFF, Class: 0xFFFF},
			9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Question
			n, err := got.Decode(tt.data, 0)
			assert.NoError(t, err, "Decode should not fail for valid data")
			assert.Equal(t, tt.want, got, "Decode should produce expected question")
			assert.Equal(t, tt.wantN, n, "Decode should return the offset just past the question")
		})
	}
}

func TestQuestionDecode_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"empty slice", []byte{}, true},
		{"only root terminator, no QTYPE/QCLASS", []byte{0x00}, true},
		{"name with missing QTYPE", []byte{0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01}, true},
		{"truncated label", []byte{0x03, 'c'}, true},
		{"self-loop pointer in name", []byte{0xC0, 0x00, 0x00, 0x01, 0x00, 0x01}, true},
		{"valid root question", []byte{0x00, 0x00, 0x01, 0x00, 0x01}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Question
			_, err := got.Decode(tt.data, 0)
			if tt.wantErr {
				assert.Error(t, err, "Decode should return error for malformed data")
			} else {
				assert.NoError(t, err, "Decode should not return error for valid data")
			}
		})
	}
}

func TestQuestionRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		question Question
	}{
		{"root", Question{Name: "", Type: A, Class: IN}},
		{"simple", Question{Name: "example.com", Type: A, Class: IN}},
		{"multi-label", Question{Name: "www.example.com", Type: AAAA, Class: IN}},
		{"MX", Question{Name: "example.com", Type: MX, Class: IN}},
		{"max type and class", Question{Name: "com", Type: 0xFFFF, Class: 0xFFFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.question.Encode()
			assert.NoError(t, err, "Encode should not fail")

			var decoded Question
			n, err := decoded.Decode(wire, 0)
			assert.NoError(t, err, "Decode should not fail on encoded data")
			assert.Equal(t, len(wire), n, "Decode offset should match Encode length")
			assert.Equal(t, tt.question, decoded, "round trip Encode → Decode should preserve all fields")
		})
	}
}

// repeatLabel builds a dotted name of n labels, each 4 bytes ("aaaa"),
// making the wire form exceed 255 bytes when n is large enough.
// 64 labels × (1 + 4) bytes + 1 root = 321 bytes > 255.
func repeatLabel(label string, count int) string {
	out := make([]byte, 0, count*(len(label)+1))
	for range count {
		out = append(out, label...)
		out = append(out, '.')
	}
	return string(out)
}
