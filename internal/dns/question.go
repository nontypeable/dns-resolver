package dns

import (
	"encoding/binary"
	"strings"
)

// QTYPE values — type of the requested resource record (RFC 1035, Section 3.2.2).
//
// The most common types a resolver deals with:
//
//	A     — IPv4 address.
//	NS    — name server (points to the server authoritative for the zone).
//	CNAME — canonical name (alias; the answer points to the real name).
//	SOA   — start of authority (zone metadata: primary NS, admin email,
//	        serial, refresh/retry/expire timers). Returned in Authority on
//	        referrals and negative answers (NXDOMAIN/NODATA) for negative caching.
//	PTR   — pointer (reverse lookup: IP → name, used under in-addr.arpa).
//	MX    — mail exchange (preference + host that accepts mail for the domain).
//	TXT   — arbitrary text records (SPF, verification tokens, etc.).
//	AAAA  — IPv6 address.
//	ANY   — request all records the server has for the name (often refused).
//
// Reference: RFC 1035, Section 3.2.2 (RR TYPE fields)
// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
const (
	A     uint16 = 1   // IPv4 address
	NS    uint16 = 2   // name server
	CNAME uint16 = 5   // canonical name (alias)
	SOA   uint16 = 6   // start of authority
	PTR   uint16 = 12  // reverse lookup
	MX    uint16 = 15  // mail exchange
	TXT   uint16 = 16  // text
	AAAA  uint16 = 28  // IPv6 address
	ANY   uint16 = 255 // any record
)

// QCLASS values — class of the query (RFC 1035, Section 3.2.4).
//
// Only IN is used in practice; CH and HS are historical.
//
//	IN — the Internet (the only class a real resolver serves).
//	CH — ChaosNET (historical; sometimes used to query server metadata).
//	HS — Hesiod (historical; not used).
//
// Reference: RFC 1035, Section 3.2.4 (RR CLASS fields)
// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
const (
	IN uint16 = 1 // Internet
	CH uint16 = 3 // ChaosNET (historical, unused)
	HS uint16 = 4 // Hesiod (historical, unused)
)

// Question is a single entry in the Question section of a DNS message.
//
// In a query it describes what the client is asking for ("give me the A
// record for www.example.com in the IN class"). The server echoes the
// Question section verbatim into its response so the client can match
// answers to queries.
//
// Bit layout (RFC 1035, Section 4.1.2):
//
//	                               1  1  1  1  1  1
//	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                                               |
//	/                     QNAME                     /
//	/                                               /
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     QTYPE                     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     QCLASS                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// QNAME is a sequence of length-prefixed labels terminated by a zero
// label: "www.example.com" is encoded as [3]www[7]example[3]com[0].
// In the Question section QNAME is never compressed; compression
// pointers (11-prefix) only appear in names inside Answer/Authority/
// Additional, where they may point back to a label in QNAME.
//
// Reference: RFC 1035, Section 4.1.2 (Question section format)
// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2
type Question struct {
	// Name is the domain being queried, in dotted notation (e.g.
	// "www.example.com"). The root domain is "." or "".
	// Encode converts it to the wire format (length-prefixed labels);
	// Decode converts the wire format back to this dotted form.
	Name string

	// Type is the QTYPE: the kind of record requested (A, AAAA, MX, ...).
	// See the QTYPE constants above. Stored as a 16-bit big-endian value.
	Type uint16

	// Class is the QCLASS: almost always IN (1). Stored as a 16-bit
	// big-endian value. See the QCLASS constants above.
	Class uint16
}

func (q Question) Encode() ([]byte, error) {
	encodedName, err := encodeName(q.Name)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 4+len(encodedName))

	copy(result[0:len(encodedName)], encodedName)
	binary.BigEndian.PutUint16(result[len(encodedName):], q.Type)
	binary.BigEndian.PutUint16(result[len(encodedName)+2:], q.Class)

	return result, nil
}

func (q *Question) Decode(data []byte, offset int) (int, error) {
	name, newOffset, err := decodeName(data, offset)
	if err != nil {
		return 0, err
	}

	if newOffset+2+2 > len(data) {
		return 0, ErrQuestionTooShort
	}

	q.Name = name
	q.Type = binary.BigEndian.Uint16(data[newOffset : newOffset+2])
	q.Class = binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4])

	return newOffset + 4, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0x0}, nil
	}

	result := make([]byte, 0, len(name)+1)
	s := strings.Split(name, ".")

	for _, v := range s {
		if v == "" {
			return nil, ErrEmptyLabel
		}
		if len(v) > 63 {
			return nil, ErrLabelTooLong
		}

		result = append(result, byte(len(v)))
		result = append(result, []byte(v)...)
	}

	result = append(result, 0x0)

	if len(result) > 255 {
		return nil, ErrNameTooLong
	}

	return result, nil
}

func decodeName(data []byte, offset int) (name string, newOffset int, err error) {
	if offset >= len(data) {
		return "", 0, ErrNameTruncated
	}

	labels := make([]string, 0)

	pos := offset
	nextOffset := -1

	for {
		if offset >= len(data) {
			return "", 0, ErrNameTruncated
		}

		b := data[pos]

		if (b & 0xC0) == 0xC0 {
			if pos+1 >= len(data) {
				return "", 0, ErrNameTruncated
			}

			if nextOffset == -1 {
				nextOffset = pos + 2
			}

			// Extract the 14-bit offset from the pointer:
			// 0x3F = 0b00111111, strips the 2-bit pointer flag,
			// leaving only the offset bits.
			target := int(data[pos]&0x3F)<<8 | int(data[pos+1])

			if target >= pos {
				return "", 0, ErrInvalidPointer
			}

			if target >= len(data) {
				return "", 0, ErrInvalidPointer
			}

			pos = target
			continue
		}

		if b&0xC0 != 0 {
			return "", 0, ErrInvalidPointer
		}

		length := int(b)

		if length == 0 {
			pos++
			break
		}

		if pos+1+length > len(data) {
			return "", 0, ErrNameTruncated
		}

		labels = append(labels, string(data[pos+1:pos+1+length]))
		pos += 1 + length
	}

	name = strings.Join(labels, ".")

	if nextOffset != -1 {
		return name, nextOffset, nil
	}

	return name, pos, nil
}
