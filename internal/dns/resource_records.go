package dns

// ResourceRecord is a single entry in the Answer, Authority, or Additional
// section of a DNS message (collectively called "resource records", or RRs).
//
// The three sections share the same wire format; they differ only in role:
//
//   - Answer     — records that directly answer the question
//     (e.g. A/AAAA records for the queried name).
//   - Authority  — NS records pointing to the next servers on a referral,
//     or a SOA record on NXDOMAIN/NODATA for negative caching.
//   - Additional — glue records (A/AAAA for the NS names in Authority)
//     and EDNS0 OPT records.
//
// The number of records in each section is given by Header.AnCount,
// Header.NsCount and Header.ArCount respectively.
//
// Bit layout (RFC 1035, Section 4.1.3):
//
//	                               1  1  1  1  1  1
//	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                                               |
//	/                     NAME                      /
//	/                                               /
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     TYPE                      |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     CLASS                     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                      TTL                      |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                   RDLENGTH                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	/                     RDATA                     /
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// Unlike the Question section, NAME here MAY use compression pointers
// (the 11-prefix form) that point back to labels earlier in the message —
// typically into the QNAME. Decode follows such pointers via decodeName;
// Encode writes the name uncompressed (a valid, if not maximally compact,
// encoding). See RFC 1035, Section 4.1.4 for the compression scheme.
//
// RDLENGTH is not stored as a field: on Encode it is derived as len(RDATA);
// on Decode it is read off the wire to know how many RDATA bytes to consume.
//
// Reference: RFC 1035, Section 4.1.3 (Resource record format)
// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3
type ResourceRecord struct {
	// Name is the owner name of the record — the domain this record
	// describes, in dotted notation (e.g. "www.example.com").
	// Encode converts it to wire format (uncompressed, length-prefixed
	// labels); Decode follows compression pointers back to dotted form.
	Name string

	// Type is the RR TYPE: the kind of record (A, NS, CNAME, MX, ...).
	// Uses the same constants as Question (A, AAAA, MX, ...).
	// Stored as a 16-bit big-endian value.
	Type uint16

	// Class is the RR CLASS: almost always IN (1).
	// Stored as a 16-bit big-endian value. See the QCLASS constants.
	Class uint16

	// TTL is the time interval, in seconds, that the record may be
	// cached before it must be re-fetched. A resolver stores this
	// alongside the record and counts it down; once it reaches 0 the
	// record is considered expired.
	// Stored as a 32-bit big-endian value.
	TTL uint32

	// RDATA is the type-specific payload of the record, as raw bytes.
	// Its interpretation depends on Type:
	//   - A     — 4 bytes, the IPv4 address.
	//   - AAAA  — 16 bytes, the IPv6 address.
	//   - NS / CNAME / PTR — a domain name in wire format
	//     (which may itself contain compression pointers).
	//   - MX    — a 16-bit preference followed by a domain name.
	//   - TXT   — one or more length-prefixed text strings.
	//   - SOA   — seven fields (mname, rname, serial, refresh, retry,
	//     expire, minimum).
	//
	// Typed parsing of RDATA is left to higher-level helpers; this
	// struct keeps the payload opaque so it can carry any record type.
	// Its wire length is RDLENGTH, which Encode derives as len(RDATA).
	RDATA []byte
}

// Encode serializes the resource record into wire format.
//
// It writes NAME (uncompressed), TYPE, CLASS, TTL, RDLENGTH = len(RDATA)
// and the RDATA bytes. The name is encoded via encodeName, so an invalid
// name (empty label, label or name too long) returns the same errors as
// Question.Encode.
func (r ResourceRecord) Encode() ([]byte, error) {
	return nil, nil
}

// Decode parses a single resource record starting at offset in data and
// returns the offset just past the consumed bytes.
//
// NAME is read via decodeName and may use compression pointers that point
// back to earlier labels in the message. After the name, it reads TYPE (2),
// CLASS (2), TTL (4) and RDLENGTH (2), then RDLENGTH bytes of RDATA.
//
// Returns:
//   - ErrResourceRecordTooShort if data ends before the fixed fields.
//   - ErrRdataTruncated if RDLENGTH exceeds the remaining bytes.
//   - name errors from decodeName (ErrNameTruncated, ErrInvalidPointer, ...).
func (r *ResourceRecord) Decode(data []byte, offset int) (int, error) {
	return 0, nil
}
