package dns

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFlagsEncode_Basic(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		want  uint16
	}{
		{"all zero", Flags{}, 0x0000},
		{"only QR", Flags{QR: true}, 0b1000_0000_0000_0000},
		{"only RD", Flags{RD: true}, 0b0000_0001_0000_0000},
		{"typical client query RD=1", Flags{RD: true}, 0b0000_0001_0000_0000},
		{"typical resolver response", Flags{QR: true, RD: true, RA: true}, 0x8180},
		{"authoritative response", Flags{QR: true, AA: true}, 0x8400},
		{"truncated response", Flags{QR: true, TC: true}, 0x8200},
		{"NXDOMAIN response", Flags{QR: true, RD: true, RA: true, RCODE: RCodeNXDomain}, 0x8183},
		{"all fields set to 1", Flags{QR: true, OPCODE: 1, AA: true, TC: true, RD: true, RA: true, Z: 1, RCODE: 1}, 0x8F91},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.Encode()
			assert.Equal(t, tt.want, got, "Encode() should produce expected packed value")
		})
	}
}

func TestFlagsEncode_IndividualFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		want  uint16
	}{
		{"QR on bit 15", Flags{QR: true}, 0b1000_0000_0000_0000},
		{"OPCODE=1 on bits 14-11", Flags{OPCODE: 1}, 0b0000_1000_0000_0000},
		{"OPCODE=15 max", Flags{OPCODE: 15}, 0b0111_1000_0000_0000},
		{"AA on bit 10", Flags{AA: true}, 0b0000_0100_0000_0000},
		{"TC on bit 9", Flags{TC: true}, 0b0000_0010_0000_0000},
		{"RD on bit 8", Flags{RD: true}, 0b0000_0001_0000_0000},
		{"RA on bit 7", Flags{RA: true}, 0b0000_0000_1000_0000},
		{"Z=1 on bits 6-4", Flags{Z: 1}, 0b0000_0000_0001_0000},
		{"Z=7 max on bits 6-4", Flags{Z: 7}, 0b0000_0000_0111_0000},
		{"RCODE=1 on bits 3-0", Flags{RCODE: 1}, 0b0000_0000_0000_0001},
		{"RCODE=15 max on bits 3-0", Flags{RCODE: 15}, 0b0000_0000_0000_1111},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.Encode()
			assert.Equal(t, tt.want, got, "Encode() should produce expected packed value")
		})
	}
}

func TestFlagsDecode_Basic(t *testing.T) {
	tests := []struct {
		name  string
		input uint16
		want  Flags
	}{
		{"all zero", 0x0000, Flags{}},
		{"only QR", 0b1000_0000_0000_0000, Flags{QR: true}},
		{"resolver response 0x8180", 0x8180, Flags{QR: true, RD: true, RA: true}},
		{"NXDOMAIN 0x8183", 0x8183, Flags{QR: true, RD: true, RA: true, RCODE: RCodeNXDomain}},
		{"all set 0x8F91", 0x8F91, Flags{QR: true, OPCODE: 1, AA: true, TC: true, RD: true, RA: true, Z: 1, RCODE: 1}},
		{"authoritative 0x8400", 0x8400, Flags{QR: true, AA: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Flags
			got.Decode(tt.input)
			assert.Equal(t, tt.want, got, "Decode() should produce expected flags struct")
		})
	}
}

func TestFlagsDecode_IndividualBits(t *testing.T) {
	tests := []struct {
		name  string
		input uint16
		want  Flags
	}{
		{"QR from bit 15", 0b1000_0000_0000_0000, Flags{QR: true}},
		{"OPCODE=1 from bits 14-11", 0b0000_1000_0000_0000, Flags{OPCODE: 1}},
		{"OPCODE=15 max", 0b0111_1000_0000_0000, Flags{OPCODE: 15}},
		{"AA from bit 10", 0b0000_0100_0000_0000, Flags{AA: true}},
		{"TC from bit 9", 0b0000_0010_0000_0000, Flags{TC: true}},
		{"RD from bit 8", 0b0000_0001_0000_0000, Flags{RD: true}},
		{"RA from bit 7", 0b0000_0000_1000_0000, Flags{RA: true}},
		{"Z=1 from bits 6-4", 0b0000_0000_0001_0000, Flags{Z: 1}},
		{"Z=7 max", 0b0000_0000_0111_0000, Flags{Z: 7}},
		{"RCODE=1 from bits 3-0", 0b0000_0000_0000_0001, Flags{RCODE: 1}},
		{"RCODE=15 max", 0b0000_0000_0000_1111, Flags{RCODE: 15}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Flags
			got.Decode(tt.input)
			assert.Equal(t, tt.want, got, "Decode() should extract the correct individual flag")
		})
	}
}

func TestFlagsRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
	}{
		{"all zero", Flags{}},
		{"only QR", Flags{QR: true}},
		{"query with RD", Flags{RD: true}},
		{"resolver response", Flags{QR: true, RD: true, RA: true}},
		{"authoritative", Flags{QR: true, AA: true}},
		{"NXDOMAIN", Flags{QR: true, RD: true, RA: true, RCODE: RCodeNXDomain}},
		{"SERVFAIL", Flags{QR: true, RD: true, RA: true, RCODE: RCodeServFail}},
		{"truncated", Flags{QR: true, TC: true, RD: true, RA: true}},
		{"OPCODE=UPDATE", Flags{QR: true, OPCODE: OpcodeUpdate}},
		{"all max", Flags{QR: true, OPCODE: 15, AA: true, TC: true, RD: true, RA: true, Z: 7, RCODE: 15}},
		{"only Z and RCODE", Flags{Z: 3, RCODE: 5}},
		{"only OPCODE", Flags{OPCODE: OpcodeQuery}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := tt.flags.Encode()
			var decoded Flags
			decoded.Decode(packed)
			assert.Equal(t, tt.flags, decoded, "round trip Encode → Decode should preserve all values")
		})
	}
}

func TestHeaderEncode_Basic(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		want   []byte
	}{
		{
			name:   "empty header",
			header: Header{},
			want:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "simple query with RD=1",
			header: Header{
				ID:      0xABCD,
				Flags:   0b0000_0001_0000_0000,
				QdCount: 1,
			},
			want: []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "resolver response with 1 answer",
			header: Header{
				ID:      0xABCD,
				Flags:   0x8180,
				QdCount: 1,
				AnCount: 1,
			},
			want: []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "authoritative response",
			header: Header{
				ID:      0x1234,
				Flags:   0x8400,
				QdCount: 1,
				AnCount: 2,
			},
			want: []byte{0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "referral with 13 NS and 13 Additional",
			header: Header{
				ID:      0xFFFF,
				Flags:   0x8000,
				QdCount: 1,
				NsCount: 13,
				ArCount: 13,
			},
			want: []byte{0xFF, 0xFF, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x0D},
		},
		{
			name: "NXDOMAIN with SOA in Authority",
			header: Header{
				ID:      0x0001,
				Flags:   0x8183,
				QdCount: 1,
				NsCount: 1,
			},
			want: []byte{0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
		},
		{
			name: "truncated response",
			header: Header{
				ID:      0x5678,
				Flags:   0x8280,
				QdCount: 1,
			},
			want: []byte{0x56, 0x78, 0x82, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "max values",
			header: Header{
				ID:      0xFFFF,
				Flags:   0xFFFF,
				QdCount: 0xFFFF,
				AnCount: 0xFFFF,
				NsCount: 0xFFFF,
				ArCount: 0xFFFF,
			},
			want: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.header.Encode()
			assert.Equal(t, tt.want, got, "Encode() should produce expected 12 bytes")
		})
	}
}

func TestHeaderDecode_Basic(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Header
	}{
		{
			name: "empty header",
			data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{},
		},
		{
			name: "simple query",
			data: []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{
				ID:      0xABCD,
				Flags:   0x0100,
				QdCount: 1,
			},
		},
		{
			name: "resolver response with answers",
			data: []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
			want: Header{
				ID:      0xABCD,
				Flags:   0x8180,
				QdCount: 1,
				AnCount: 1,
			},
		},
		{
			name: "referral",
			data: []byte{0xFF, 0xFF, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x0D},
			want: Header{
				ID:      0xFFFF,
				Flags:   0x8000,
				QdCount: 1,
				NsCount: 13,
				ArCount: 13,
			},
		},
		{
			name: "NXDOMAIN",
			data: []byte{0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
			want: Header{
				ID:      0x0001,
				Flags:   0x8183,
				QdCount: 1,
				NsCount: 1,
			},
		},
		{
			name: "max values",
			data: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			want: Header{
				ID:      0xFFFF,
				Flags:   0xFFFF,
				QdCount: 0xFFFF,
				AnCount: 0xFFFF,
				NsCount: 0xFFFF,
				ArCount: 0xFFFF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Header
			err := got.Decode(tt.data)
			assert.NoError(t, err, "Decode() should not return error for valid data")
			assert.Equal(t, tt.want, got, "Decode() should produce expected header")
		})
	}
}

func TestHeaderDecode_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"empty slice", []byte{}, true},
		{"1 byte", []byte{0x00}, true},
		{"5 bytes", []byte{0x00, 0x01, 0x02, 0x03, 0x04}, true},
		{"11 bytes — one short", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}, true},
		{"12 bytes — valid", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}, false},
		{"13 bytes — extra data is ok", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Header
			err := got.Decode(tt.data)
			if tt.wantErr {
				assert.Error(t, err, "Decode() should return error for insufficient data")
			} else {
				assert.NoError(t, err, "Decode() should not return error for valid data")
			}
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{"empty", Header{}},
		{"simple query", Header{ID: 0xABCD, Flags: 0x0100, QdCount: 1}},
		{"resolver response", Header{ID: 0xABCD, Flags: 0x8180, QdCount: 1, AnCount: 1}},
		{"authoritative", Header{ID: 0x1234, Flags: 0x8400, QdCount: 1, AnCount: 2}},
		{"referral", Header{ID: 0xFFFF, Flags: 0x8000, QdCount: 1, NsCount: 13, ArCount: 13}},
		{"NXDOMAIN", Header{ID: 0x0001, Flags: 0x8183, QdCount: 1, NsCount: 1}},
		{"truncated", Header{ID: 0x5678, Flags: 0x8280, QdCount: 1}},
		{"max values", Header{ID: 0xFFFF, Flags: 0xFFFF, QdCount: 0xFFFF, AnCount: 0xFFFF, NsCount: 0xFFFF, ArCount: 0xFFFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.header.Encode()
			assert.Len(t, encoded, 12, "Encode() should always produce 12 bytes")

			var decoded Header
			err := decoded.Decode(encoded)
			assert.NoError(t, err, "Decode() should not fail on encoded data")

			assert.Equal(t, tt.header, decoded, "round trip Encode → Decode should preserve all fields")
		})
	}
}
