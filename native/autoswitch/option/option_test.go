package option

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizedFillsDefaultsAndClamps(t *testing.T) {
	got := Settings{Groups: []string{" A ", "", "A", "B"}, FailureThreshold: 99, Interval: 1, Timeout: -1}.Normalized()
	want := Settings{
		Groups:           []string{"A", "B"},
		FailureThreshold: 10,
		Interval:         10,
		Timeout:          1000,
		Concurrency:      DefaultConcurrency,
		URL:              DefaultURL,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalized() = %+v, want %+v", got, want)
	}
}

func TestValidate(t *testing.T) {
	for name, test := range map[string]struct {
		settings Settings
		valid    bool
	}{
		"disabled without groups": {Settings{}, true},
		"enabled without groups":  {Settings{Enable: true, Groups: []string{" "}}, false},
		"invalid filter":          {Settings{PreferredFilter: "("}, false},
		"invalid expected status": {Settings{ExpectedStatus: "abc"}, false},
		"negative expected delay": {Settings{ExpectedDelay: -1}, false},
		"large expected delay":    {Settings{ExpectedDelay: 100000}, false},
		"zero expected delay":     {Settings{ExpectedDelay: 0}, true},
		"maximum expected delay":  {Settings{ExpectedDelay: 99999}, true},
		"enabled with lookbehind": {Settings{Enable: true, Groups: []string{"G"}, PreferredFilter: `(?i)(?<![A-Za-z])UK(?![A-Za-z])`}, true},
	} {
		if err := test.settings.Validate(); (err == nil) != test.valid {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
}

func TestExpectedDelayAndFailureDefaults(t *testing.T) {
	if got := (Settings{}).Normalized(); got.FailureThreshold != 1 || got.ExpectedDelay != 0 {
		t.Fatalf("defaults = %+v", got)
	}
	for _, test := range []struct{ input, want int }{{-1, 0}, {0, 0}, {100, 100}, {99999, 99999}, {100000, 99999}} {
		if got := (Settings{ExpectedDelay: test.input}).Normalized().ExpectedDelay; got != test.want {
			t.Errorf("Normalized expected-delay %d = %d, want %d", test.input, got, test.want)
		}
	}
	var settings Settings
	if err := json.Unmarshal([]byte(`{"expected-delay":120}`), &settings); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil || fields["expected-delay"] != float64(120) {
		t.Fatalf("JSON round trip = %s, error = %v", data, err)
	}
}

func TestPreferredFilterIsTokenAware(t *testing.T) {
	filter, err := Settings{PreferredFilter: `(?i)(?<![A-Za-z])UK(?![A-Za-z])`}.CompileFilter()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"UK 01": true, "🇬🇧 uk-2": true, "Ukraine 01": false, "Duke": false} {
		if got, _ := filter.MatchString(name); got != want {
			t.Errorf("MatchString(%q) = %v, want %v", name, got, want)
		}
	}
}
