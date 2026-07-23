package dns

import "errors"

var (
	ErrHeaderTooShort = errors.New("header requires 12 bytes")

	// Question / QNAME errors (RFC 1035, Section 4.1.4)
	ErrNameTooLong      = errors.New("domain name exceeds 255 bytes")
	ErrLabelTooLong     = errors.New("label exceeds 63 bytes")
	ErrEmptyLabel       = errors.New("empty label in domain name")
	ErrNameTruncated    = errors.New("domain name is truncated")
	ErrInvalidPointer   = errors.New("invalid or looping compression pointer")
	ErrQuestionTooShort = errors.New("question requires QTYPE and QCLASS")
)
