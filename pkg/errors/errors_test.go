package errors_test

import (
	"errors"
	"testing"

	alterrors "alt/pkg/errors"
)

func TestErrors(t *testing.T) {
	cause := errors.New("connection refused")
	err := alterrors.Wrap(alterrors.CodeSignalingUnavailable, "failed to reach signaling endpoint", cause)

	if !alterrors.IsCode(err, alterrors.CodeSignalingUnavailable) {
		t.Fatalf("expected CodeSignalingUnavailable")
	}
	if alterrors.IsCode(err, alterrors.CodeNameNotFound) {
		t.Fatalf("unexpected CodeNameNotFound match")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected errors.Is to match underlying cause")
	}
}

