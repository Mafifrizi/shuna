package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ExitOK                = 0
	ExitUsage             = 1
	ExitPolicyStop        = 2
	ExitMissing           = 3
	ExitCorruptCiphertext = 4
)

// StatusName returns the canonical status string for an exit code.
func StatusName(code int) string {
	switch code {
	case ExitOK:
		return "OK"
	case ExitUsage:
		return "USAGE"
	case ExitPolicyStop:
		return "POLICY_STOP"
	case ExitMissing:
		return "MISSING"
	case ExitCorruptCiphertext:
		return "CORRUPT_CIPHERTEXT"
	default:
		return "UNKNOWN"
	}
}

// ExitError maps an error to one of the 5 semantic Shuna exit codes.
type ExitError struct {
	Code    int
	Status  string
	Message string
	Err     error
}

func (e *ExitError) Error() string {
	if e.Err != nil && e.Message != "" {
		return fmt.Sprintf("%s (%s): %v", e.Status, e.Message, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Status, e.Message)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Status, e.Err)
	}
	return e.Status
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// NewError creates a typed ExitError with an explicit semantic status override.
func NewError(code int, status string, msg string, err error) *ExitError {
	if status == "" {
		status = StatusName(code)
	}
	return &ExitError{
		Code:    code,
		Status:  status,
		Message: msg,
		Err:     err,
	}
}

// CodeOf extracts the semantic exit code from err, defaulting to ExitUsage if untyped.
func CodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitUsage
}

// StatusOf extracts the semantic status string from err.
func StatusOf(err error) string {
	if err == nil {
		return StatusName(ExitOK)
	}
	var ee *ExitError
	if errors.As(err, &ee) && ee.Status != "" {
		return ee.Status
	}
	return StatusName(CodeOf(err))
}

// Envelope is the standard JSON CLI output envelope.
type Envelope struct {
	OK      bool   `json:"ok"`
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// WriteJSON writes a structured Envelope to w.
func WriteJSON(w io.Writer, code int, status string, msg string, data any, err error) error {
	if status == "" {
		status = StatusName(code)
	}
	env := Envelope{
		OK:      code == ExitOK,
		Code:    code,
		Status:  status,
		Message: msg,
		Data:    data,
	}
	if err != nil {
		env.Error = err.Error()
		if status == "" || status == StatusName(code) {
			env.Status = StatusOf(err)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(env)
}
