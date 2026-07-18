package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		expect  string
		error   error
	}{
		{
			name:    "no auth header",
			headers: http.Header{"Authorization": {}},
			expect:  "",
			error:   ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty auth header",
			headers: http.Header{},
			expect:  "",
			error:   ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed auth header",
			headers: http.Header{"Authorization": {"Bearer token"}},
			expect:  "",
			error:   errors.New("malformed authorization header"),
		},
		{
			name:    "wrong auth prefix",
			headers: http.Header{"Authorization": {"WrongPrefix token"}},
			expect:  "",
			error:   errors.New("malformed authorization header"),
		},
		{
			name:    "valid auth header",
			headers: http.Header{"Authorization": {"ApiKey myKey123"}},
			expect:  "myKey123",
			error:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetAPIKey(tt.headers)
			if result != tt.expect {
				t.Errorf("expected result %q, got %q", tt.expect, result)
			}
			if tt.error == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else if tt.error != nil {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.error)
				} else if tt.error.Error() != err.Error() {
					t.Errorf("expected error %q, got %q", tt.error, err)
				}
			}
		})
	}
}
