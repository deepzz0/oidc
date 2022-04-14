// Package protocol provides ...
package protocol

import (
	"encoding/json"
	"strings"

	"golang.org/x/text/language"
)

// SpaceDelimitedArr space delimited string
type SpaceDelimitedArr []string

// Encode implements schema
func (s SpaceDelimitedArr) Encode() string {
	return strings.Join(s, " ")
}

// UnmarshalText unmarhsal text
func (s *SpaceDelimitedArr) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

// MarshalText marhsal text
func (s SpaceDelimitedArr) MarshalText() ([]byte, error) {
	return []byte(s.Encode()), nil
}

// MarshalJSON marshal json
func (s SpaceDelimitedArr) MarshalJSON() ([]byte, error) {
	return json.Marshal((s).Encode())
}

// UnmarshalJSON unmarhsal json
func (s *SpaceDelimitedArr) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = strings.Split(str, " ")
	return nil
}

// Locales local tag
type Locales []language.Tag

// UnmarshalText unmarhsal text
func (l *Locales) UnmarshalText(text []byte) error {
	locales := strings.Split(string(text), " ")
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			*l = append(*l, tag)
		}
	}
	return nil
}
