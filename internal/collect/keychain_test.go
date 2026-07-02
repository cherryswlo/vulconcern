package collect

import "testing"

func TestIsMissingKeychainItemOutput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want bool
	}{
		{
			name: "security missing item stderr",
			raw:  []byte("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n"),
			want: true,
		},
		{
			name: "generic missing item",
			raw:  []byte("could not be found"),
			want: true,
		},
		{
			name: "other error",
			raw:  []byte("User interaction is not allowed."),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMissingKeychainItemOutput(tt.raw); got != tt.want {
				t.Fatalf("isMissingKeychainItemOutput(%q) = %v, want %v", string(tt.raw), got, tt.want)
			}
		})
	}
}
