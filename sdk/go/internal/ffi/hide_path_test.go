package ffi

import (
	"errors"
	"testing"
)

func TestHidePathNativeCompatibility(t *testing.T) {
	hidden := map[string]MountSpec{"/data": {Bind: "/tmp/d", HidePath: []string{".env"}}}
	plain := map[string]MountSpec{"/data": {Bind: "/tmp/d"}}
	for _, tc := range []struct {
		name      string
		volumes   map[string]MountSpec
		supported bool
		wantError bool
	}{
		{"old library refuses a hide-path list", hidden, false, true},
		{"old library accepts mounts without hide-path", plain, false, false},
		{"old library accepts no mounts", nil, false, false},
		{"current library accepts a hide-path list", hidden, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHidePathSupport(tc.volumes, tc.supported)
			if !tc.wantError {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var nativeError *Error
			if !errors.As(err, &nativeError) || nativeError.Kind != KindUnsupportedOperation {
				t.Fatalf("want unsupported-operation error, got %v", err)
			}
		})
	}
}
