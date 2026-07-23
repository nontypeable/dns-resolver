package dns

import "errors"

var (
	ErrHeaderTooShort = errors.New("header requires 12 bytes")
)
