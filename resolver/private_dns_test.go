package resolver

import (
	"testing"

	"github.com/go-chi/chi"
	"github.com/stgnet/blocky/config"
)

func TestBlockingResolver_getPort(t *testing.T) {
	type args struct {
		groupsToCheck []string
	}
	tests := []struct {
		name          string
		blockingCfg   config.BlockingConfig
		groupsToCheck []string
		want          int
	}{
		{
			name: "client malware true and adblock missing with global adblock true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"malware"},
				},
				Global: map[string]bool{"adblock": true},
			},
			groupsToCheck: []string{"malware"},
			want:          1026,
		},
		{
			name: "global and client adblock true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock"},
				},
				Global: map[string]bool{"adblock": true},
			},
			groupsToCheck: []string{"adblock"},
			want:          1025,
		},
		{
			name: "global and client adblock true, adult client",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult"},
				},
				Global: map[string]bool{"adblock": true},
			},
			groupsToCheck: []string{"adblock", "adult"},
			want:          1029,
		},
		{
			name: "global adblock false, client true. Client adult",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult"},
				},
				Global: map[string]bool{"adblock": false},
			},
			groupsToCheck: []string{"adblock", "adult"},
			want:          1028,
		},
		{
			name: "all enabled",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult", "malware"},
				},
				Global: map[string]bool{"adblock": true},
			},
			groupsToCheck: []string{"adblock", "adult", "malware"},
			want:          1031,
		},
		{
			name: "no client, global adblock true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {},
				},
				Global: map[string]bool{"adblock": true},
			},
			groupsToCheck: []string{},
			want:          1024,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBlockingResolver(chi.NewRouter(), tt.blockingCfg).(*BlockingResolver)
			if got := r.getPort(tt.groupsToCheck); got != tt.want {
				t.Errorf("BlockingResolver.getPort() = %v, want %v", got, tt.want)
			}
		})
	}
}
