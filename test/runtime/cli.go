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

package RuntimeTest

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeValidatedCLI", func() {

	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	var once sync.Once

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeCLI"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed("cilium endpoint list")
		}
	})

	Context("Identity CLI testing", func() {
		It("Test labelsSHA256", func() {
			fooID := "id.foo"
			namesLabels := [][]string{{"foo", fooID}, {"bar", "id.bar"}, {"baz", "id.baz"}}

			for _, set := range namesLabels {
				res := vm.ContainerCreate(set[0], helpers.NetperfImage, helpers.CiliumDockerNetwork, fmt.Sprintf("-l %s", set[1]))
				defer vm.ContainerRm(set[0])
				res.ExpectSuccess("Unable to create container: %s", res.CombineOutput())
			}
			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue(), "endpoints not ready")

			epModel := vm.EndpointGet(fmt.Sprintf("-l container:%s", fooID))
			Expect(epModel).ShouldNot(BeNil(), "no endpoint model returned")
			identity := epModel.Identity.ID

			out, err := vm.ExecCilium(fmt.Sprintf("identity get %d -o json", identity)).Filter("{[0].labelsSHA256}")

			Expect(err).Should(BeNil(), "error getting SHA from identity")
			fooSha := "7c5b1431262baa7f060728b6252abf6a42d9b39f38328d896b37755b1c578477"
			Expect(out.String()).Should(Equal(fooSha))
		})

		It("test identity list", func() {
			By("Testing 'cilium identity list' for an endpoint's identity")
			fooID := "id.foo"
			namesLabels := [][]string{{"foo", fooID}, {"bar", "id.bar"}, {"baz", "id.baz"}}

			for _, set := range namesLabels {
				res := vm.ContainerCreate(set[0], helpers.NetperfImage, helpers.CiliumDockerNetwork, fmt.Sprintf("-l %s", set[1]))
				defer vm.ContainerRm(set[0])
				res.ExpectSuccess("Unable to create container: %s", res.CombineOutput())
			}

			epModel := vm.EndpointGet(fmt.Sprintf("-l container:%s", fooID))
			Expect(epModel).ShouldNot(BeNil(), "no endpoint model returned")
			identity := strconv.FormatInt(epModel.Identity.ID, 10)

			res := vm.ExecCilium(fmt.Sprintf("identity list container:%s", fooID))
			res.ExpectSuccess(fmt.Sprintf("Unable to get identity list output for label container:%s", fooID))

			resSingleOut := res.SingleOut()

			containsIdentity := strings.Contains(resSingleOut, identity)
			Expect(containsIdentity).To(BeTrue(), "identity %s from 'cilium endpoint get' for endpoint %s not in 'cilium identity list' output", identity, resSingleOut)

			By("Testing 'cilium identity list' for reserved identities")
			res = vm.Exec(`cilium identity list`)
			resSingleOut = res.SingleOut()

			reservedIdentities := []string{"health", "cluster", "host", "world"}

			for _, id := range reservedIdentities {
				By(fmt.Sprintf("checking that reserved identity '%s' is in 'cilium identity list' output", id))
				containsReservedIdentity := strings.Contains(resSingleOut, id)
				Expect(containsReservedIdentity).To(BeTrue(), "reserved identity '%s' not in 'cilium identity list' output", id)
			}
		})
	})

})
