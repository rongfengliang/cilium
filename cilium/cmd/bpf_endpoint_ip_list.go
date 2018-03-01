// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/command"

	"github.com/cilium/cilium/pkg/maps/remotelxcmap"
	"github.com/spf13/cobra"
)

const (
	ipAddrTitle             = "IP ADDRESS"
	remoteEndpointInfoTitle = "REMOTE ENDPOINT INFO"
)

var bpfEndpointIpListCmd = &cobra.Command{
	Use:   "ip list",
	Short: "List remote endpoint IPs and their corresponding security identities",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint ip list")

		bpfEndpointIpList := make(map[string][]string)
		if err := remotelxcmap.RemoteLXCMap.Dump(bpfEndpointIpList); err != nil {
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfEndpointIpList); err != nil {
				os.Exit(1)
			}
			return
		}

		TablePrinter(ipAddrTitle, remoteEndpointInfoTitle, bpfEndpointIpList)
	},
}

func init() {
	bpfEndpointCmd.AddCommand(bpfEndpointIpListCmd)
	command.AddJSONOutput(bpfEndpointIpListCmd)
}
