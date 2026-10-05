package ui

import (
	"strings"
	"testing"
)

func TestParseKeyPassFile(t *testing.T) {
	tests := []struct {
		testName    string
		input       string
		expErr      string
		passesCount int
		key         string
		keyAbsent   bool
		pass        string
	}{
		{
			testName:    "Has pass",
			input:       "\n# comment\nthekey:gazonk\n  # spacecomment\n  \n",
			passesCount: 1,
			key:         "thekey",
			pass:        "gazonk",
		},
		{
			testName:    "Has pass #2",
			input:       "somekey:foo\nthekey:gazonk\notherkey:bar",
			passesCount: 3,
			key:         "thekey",
			pass:        "gazonk",
		},
		{
			testName:    "Has pass with colon",
			input:       "\n# comment\nthekey:gazonk:ok\n",
			passesCount: 1,
			key:         "thekey",
			pass:        "gazonk:ok",
		},
		{
			testName:    "Missing pass",
			input:       "otherkey:foo\n",
			passesCount: 1,
			key:         "thekey",
			keyAbsent:   true,
		},
		{
			testName: "Line has duplicate key",
			input:    "akey:foo\nakey:bar\n",
			expErr:   `2: duplicate key-file "akey"`,
		},
		{
			testName: "Line does not follow format",
			input:    "bubblebobble",
			expErr:   "1: not in format 'key-file:passphrase'",
		},
		{
			testName: "Line missing key",
			input:    ":pass",
			expErr:   "1: key-file or passphrase is empty",
		},
		{
			testName: "Line missing pass",
			input:    "key:",
			expErr:   "1: key-file or passphrase is empty",
		},
		{
			testName:    "Has no passes",
			input:       "\n# comment\n\n\n",
			passesCount: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			passes, err := parseKeyPassFile(strings.NewReader(test.input))

			if err != nil {
				if test.expErr == "" {
					t.Errorf("got parse err %q, wanted no err", err)
				} else if err.Error() != test.expErr {
					t.Errorf("got parse err %q, wanted %q", err, test.expErr)
				}
				return
			}
			if test.expErr != "" {
				t.Errorf("parse with no err, wanted err %q", test.expErr)
				return
			}

			if test.passesCount != len(passes) {
				t.Errorf("got %d passphrases, wanted %d", len(passes), test.passesCount)
				return
			}
			if test.passesCount == 0 {
				return
			}

			if test.key == "" {
				t.Fatalf("must have non-empty key")
			}
			got, ok := passes[test.key]
			if test.keyAbsent {
				if ok {
					t.Errorf("key %q exists, expected absent", test.key)
				}
				return
			}
			if !ok {
				t.Errorf("key %q absent, expected existing", test.key)
				return

			}

			if got != test.pass {
				t.Errorf("key %q: got pass %q, wanted %q", test.key, got, test.pass)
			}
		})
	}
}
