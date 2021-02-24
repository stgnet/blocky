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
			want:          1024,
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
			// INFO      clientGroupsBlock                        prefix=server
			// INFO        192.168.176.116 = "adult"              prefix=server
			// INFO        192.168.176.185 = "adult"              prefix=server
			// INFO        192.168.176.245 = "adult"              prefix=server
			// INFO        default = "adblock"                    prefix=server
			// INFO      global:                                  prefix=server
			// INFO        adblock = "true"                       prefix=server
			// INFO        adult = "true"                         prefix=server
			// INFO        malware = "false"                      prefix=server

			name: "global and client adblock adult true",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true},
			},
			groupsToCheck: []string{"adult"},
			want:          1028,
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
			want:          1025,
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
			want:          1024,
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
			want:          1025,
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
		{
			name: "everything on",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult", "malware"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": true},
			},
			groupsToCheck: []string{"adblock", "adult", "malware"},
			want:          1031,
		},
		{
			name: "global malware off",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult", "malware"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": false},
			},
			groupsToCheck: []string{"adblock", "adult", "malware"},
			want:          1029,
		},
		{
			name: "global malware off, missing client",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": false},
			},
			groupsToCheck: []string{"adblock", "adult"},
			want:          1029,
		},
		{
			name: "multiple client to check",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adblock", "adult"},
					"1.2.1.3": {"adult"},
				},
				Global: map[string]bool{"adblock": true, "adult": true, "malware": false},
			},
			groupsToCheck: []string{"adblock", "adult"},
			want:          1029,
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
