// Package protocol provides ...
package protocol

import (
	"encoding/json"
	"strings"
	"time"

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

// Time time
type Time time.Time

// UnmarshalJSON unmarshal json
func (t *Time) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	*t = Time(time.Unix(i, 0).UTC())
	return nil
}

// MarshalJSON marshal json
func (t *Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(*t).UTC().Unix())
}

// Audience audience
type Audience []string

// UnmarshalJSON unmarshal json
func (a *Audience) UnmarshalJSON(text []byte) error {
	var i interface{}
	err := json.Unmarshal(text, &i)
	if err != nil {
		return err
	}
	switch aud := i.(type) {
	case []interface{}:
		*a = make([]string, len(aud))
		for i, audience := range aud {
			(*a)[i] = audience.(string)
		}
	case string:
		*a = []string{aud}
	}
	return nil
}
