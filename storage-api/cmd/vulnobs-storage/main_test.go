package main

import "testing"

func TestRetentionDaysFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "default", want: 90},
		{name: "configured", value: "30", want: 30},
		{name: "zero", value: "0", wantErr: true},
		{name: "invalid", value: "forever", wantErr: true},
		{name: "too large", value: "3651", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("VULNOBS_RETENTION_DAYS", test.value)
			got, err := retentionDaysFromEnv()
			if (err != nil) != test.wantErr {
				t.Fatalf("retentionDaysFromEnv() error = %v, wantErr %t", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Fatalf("retentionDaysFromEnv() = %d, want %d", got, test.want)
			}
		})
	}
}
