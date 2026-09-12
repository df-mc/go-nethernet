package nethernet

import "testing"

func TestSignalUnmarshalText(t *testing.T) {
	for _, test := range []struct {
		text  string
		id    uint64
		valid bool
	}{
		{"CONNECTERROR 42 12", 42, true},
		{"CONNECTERROR 42junk -12suffix", 42, true},
		{"CONNECTERROR 0x10 0x10", 0, true},
		{"CONNECTERROR 18446744073709551615 2147483647", ^uint64(0), true},
		{"CONNECTERROR 42 -2147483648", 42, true},
		{"CONNECTERROR 42 2147483648", 0, false},
		{"CONNECTERROR 42 -2147483649", 0, false},
		{"CONNECTERROR 42 invalid", 0, false},
		{"CONNECTERROR 42 ", 0, false},
		{"CONNECTERROR 42 -", 0, false},
		{"CONNECTERROR 42 +12", 0, false},
		{"CONNECTERROR 42  12", 0, false},
		{"CONNECTERROR 42\t12", 0, false},
		{"CONNECTERROR 18446744073709551616 12", 0, false},
		{"CONNECTERROR -42 12", 0, false},
		{"CONNECTERROR +42 12", 0, false},
		{"CONNECTERROR  42 12", 0, false},
		{"CONNECTERROR invalid 12", 0, false},
		{"UNKNOWN 42 12", 0, false},
		{"connecterror 42 12", 0, false},
		{"CONNECTREQUEST 42junk offer data", 42, true},
		{"CONNECTRESPONSE 42junk answer data", 42, true},
		{"CANDIDATEADD 42junk candidate data", 42, true},
	} {
		t.Run(test.text, func(t *testing.T) {
			var signal Signal
			err := signal.UnmarshalText([]byte(test.text))
			if (err == nil) != test.valid {
				t.Fatalf("UnmarshalText() error = %v, valid = %t", err, test.valid)
			}
			if test.valid && signal.ConnectionID != test.id {
				t.Fatalf("ConnectionID = %d, want %d", signal.ConnectionID, test.id)
			}
		})
	}
}

func TestParseSignalErrorCode(t *testing.T) {
	for _, test := range []struct {
		data string
		want int64
	}{
		{"0", 0},
		{"0x10", 0},
		{"12junk", 12},
		{"12 ", 12},
		{"-12suffix", -12},
		{"2147483647", 2147483647},
		{"-2147483648", -2147483648},
		{"0000000000000000000000000000000000000012", 12},
	} {
		t.Run(test.data, func(t *testing.T) {
			got, err := parseSignalErrorCode(test.data)
			if err != nil || got != test.want {
				t.Fatalf("parseSignalErrorCode(%q) = %d, %v; want %d, nil", test.data, got, err, test.want)
			}
		})
	}
}
