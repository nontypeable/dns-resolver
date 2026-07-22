package dns

// RCODE values (RFC 1035, Section 4.1.1)
const (
	RCodeNoError  uint8 = 0
	RCodeFormErr  uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeNotImp   uint8 = 4
	RCodeRefused  uint8 = 5
)

// OPCODE values (RFC 1035, Section 4.1.1)
const (
	OpcodeQuery  uint8 = 0
	OpcodeIQuery uint8 = 1
	OpcodeStatus uint8 = 2
	OpcodeNotify uint8 = 4
	OpcodeUpdate uint8 = 5
)

// Header is the first 12 bytes of any DNS message (query or response).
//
// Reference: RFC 1035, Section 4.1.1 (Header section format)
// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
type Header struct {
	// ID is a transaction identifier (0–65535).
	// The client generates a random ID when sending a query.
	// The server MUST copy the same ID into its response.
	// Used to match responses to queries (critical for UDP,
	// where responses may arrive out of order).
	ID uint16

	// Flags is a 16-bit field packed with control flags and the response code.
	// See the Flags type and its Pack/Unpack methods for working with individual bits.
	Flags uint16

	// QdCount is the number of entries in the Question section.
	// In practice, almost always 1 (DNS does not support batch queries).
	// The server copies this value into its response.
	QdCount uint16

	// AnCount is the number of resource records in the Answer section.
	// Always 0 in a query. In a response, indicates how many records the server returned.
	//
	// A value of 0 in a response means one of:
	//   - Referral: the server does not know the answer, but points to
	//     other servers (see NsCount for NS records in Authority).
	//   - NXDOMAIN: the domain does not exist (RCODE = 3).
	//   - NODATA: the domain exists, but there are no records of the requested type
	//     (RCODE = 0, Answer is empty).
	AnCount uint16

	// NsCount is the number of resource records in the Authority section.
	// Always 0 in a query.
	//
	// In a response:
	//   - On referral: contains NS records pointing to the next-level servers.
	//   - On NXDOMAIN/NODATA: contains a SOA record with the TTL for negative caching.
	NsCount uint16

	// ArCount is the number of resource records in the Additional section.
	// Usually 0 in a query (or 1 if EDNS0 is used).
	//
	// In a response, contains glue records — A/AAAA records for the NS servers
	// listed in the Authority section. This saves the resolver from making
	// a separate query to resolve the NS server's IP address.
	ArCount uint16
}

func (h Header) Encode() []byte {
	return []byte{}
}

func (h *Header) Decode(data []byte) error {
	return nil
}

// Flags is the unpacked representation of the 16-bit flags field in Header.
// Each bit (or group of bits) controls DNS protocol behavior.
// Use Pack() to serialize into a uint16, and Unpack() to parse one back.
//
// Bit layout (RFC 1035, Section 4.1.1):
//
//	                               1  1  1  1  1  1
//	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//		|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// Reference: RFC 1035, Section 4.1.1
// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
type Flags struct {
	// QR (1 bit) — Query/Response.
	// 0 = this message is a query.
	// 1 = this message is a response.
	QR bool

	// OPCODE (4 bits) — type of operation.
	// 0 = QUERY (standard query, used in 95% of cases).
	// 1 = IQUERY (inverse query, deprecated).
	// 2 = STATUS (server status request).
	// 4 = NOTIFY (zone change notification).
	// 5 = UPDATE (dynamic zone update).
	OPCODE uint8

	// AA (1 bit) — Authoritative Answer.
	//
	// Set by the server in a response:
	//   1 = the answer comes from a server that is authoritative for the zone
	//       (i.e. the server officially manages this domain and stores its records).
	//   0 = the answer comes from a recursive resolver or is a referral.
	//
	// The resolver uses this bit to decide whether the answer is final
	// and can be cached, or whether it should continue iterating down the DNS tree.
	AA bool

	// TC (1 bit) — Truncation.
	// 1 = the response was too large to fit in a UDP packet and was truncated.
	// The resolver MUST re-issue the query over TCP to get the full response.
	TC bool

	// RD (1 bit) — Recursion Desired.
	// Set by the client in a query:
	//   1 = "please perform recursion for me and return the final answer".
	//   0 = "just give me a referral, I will iterate myself".
	//
	// A resolver sets RD=0 when querying root/TLD/authoritative servers
	// (it performs recursion itself). A stub client (e.g. a browser) sets RD=1.
	RD bool

	// RA (1 bit) — Recursion Available.
	// Set by the server in a response:
	//   1 = this server supports recursive resolution.
	//   0 = this server does not perform recursion.
	//
	// Root and TLD servers return RA=0 (they only give referrals).
	// Recursive resolvers (8.8.8.8, 1.1.1.1) return RA=1.
	RA bool

	// Z (3 bits) — Reserved.
	// Must be 0 per RFC 1035.
	Z uint8

	// RCODE (4 bits) — Response code.
	// 0 = NOERROR (success, or NODATA if Answer is empty).
	// 1 = FORMERR (server could not parse the query).
	// 2 = SERVFAIL (server failure, try another server).
	// 3 = NXDOMAIN (the domain does not exist).
	// 4 = NOTIMP (server does not support this type of query).
	// 5 = REFUSED (server refused to answer, e.g. due to policy).
	RCODE uint8
}

func (f Flags) Encode() uint16 {
	return 0
}

func (f *Flags) Decode(flags uint16) {}
