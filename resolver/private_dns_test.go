package resolver

import (
	"testing"

	"github.com/go-chi/chi"
	"github.com/stgnet/blocky/config"
	"github.com/stretchr/testify/assert"
)

func Test_GetPort(t *testing.T) {

	sutConfig := config.BlockingConfig{
		BlackLists: map[string][]string{
			"adblock": {""},
		},
		ClientGroupsBlock: map[string][]string{
			"1.2.1.2": {"malware"},
		},
		Global: map[string]bool{"adblock": true},
	}
	sut := NewBlockingResolver(chi.NewRouter(), sutConfig).(*BlockingResolver)

	port := sut.getPort

	assert.Equal(t, 1027, port)

}
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
			name: "malware and adblock",
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
			want:          1027,
		},
		{
			name: "duplicated block",
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
			name: "no groups to check",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adult"},
				},
				Global: map[string]bool{"adult": true},
			},
			groupsToCheck: []string{""},
			want:          1028,
		},
		{
			name: "Multiple block from client",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adult", "malware"},
				},
				Global: map[string]bool{"adult": true},
			},
			groupsToCheck: []string{"adult", "malware"},
			want:          1030,
		},
		{
			name: "false global, gets picked up client",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adult", "malware"},
				},
				Global: map[string]bool{"adult": false},
			},
			groupsToCheck: []string{"adult", "malware"},
			want:          1030,
		},
		{
			name: "false global",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adult", "malware"},
				},
				Global: map[string]bool{"adult": false},
			},
			groupsToCheck: []string{"malware"},
			want:          1026,
		},
		{
			name: "mixed global, empty group",
			blockingCfg: config.BlockingConfig{
				BlackLists: map[string][]string{
					"adblock": {""},
				},
				ClientGroupsBlock: map[string][]string{
					"1.2.1.2": {"adult", "malware"},
				},
				Global: map[string]bool{"adult": false, "malware": true},
			},
			groupsToCheck: []string{""},
			want:          1026,
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
