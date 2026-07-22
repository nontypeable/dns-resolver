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
