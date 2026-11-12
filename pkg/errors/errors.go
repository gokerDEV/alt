package errors

import "fmt"

// Code represents a canonical ALT failure classification as defined in §13.
type Code string

const (
	CodeNameNotFound         Code = "NAME_NOT_FOUND"
	CodeRecordUnavailable    Code = "RECORD_UNAVAILABLE"
	CodeOwnershipExpired     Code = "OWNERSHIP_EXPIRED"
	CodeTargetExpired        Code = "TARGET_EXPIRED"
	CodePublisherOffline     Code = "PUBLISHER_OFFLINE"
	CodeSignalingUnavailable Code = "SIGNALING_UNAVAILABLE"
	CodeDirectConnectFailed  Code = "DIRECT_CONNECT_FAILED"
	CodeOriginTLSError       Code = "ORIGIN_TLS_ERROR"
	CodeLocalSetupRequired   Code = "LOCAL_SETUP_REQUIRED"
	CodeInvalidConfig        Code = "INVALID_CONFIG"
)

// Error encapsulates a structured ALT error with a machine-readable Code,
// a human-readable message, and an optional underlying cause.
type Error struct {
	Code    Code
	Message string
	Cause   error
}

// New creates a new structured ALT Error with the given Code and message.
func New(code Code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// Wrap creates a new structured ALT Error wrapping an underlying error.
func Wrap(code Code, message string, cause error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// IsCode checks whether err or any error in its chain has the given Code.
func IsCode(err error, code Code) bool {
	for err != nil {
		if ae, ok := err.(*Error); ok && ae.Code == code {
			return true
		}
		if u, ok := err.(interface{ Unwrap() error }); ok {
			err = u.Unwrap()
		} else {
			break
		}
	}
	return false
}

