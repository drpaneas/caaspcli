// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"
)

var cfgFile string

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup cassp cluster",
	Long: `Setup caasp clsuter.

Example:

caaspcli setup --file configuration.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := os.Open(cfgFile)
		if err != nil {
			return err
		}
		b, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		r := &Setup{}
		yaml.Unmarshal(b, r)
		fmt.Printf("config: %v\n", r)

		step := exec.Command("docker", "version")
		resp, err := step.CombinedOutput()
		if err != nil {
			return err
		}
		fmt.Printf("%s \n", string(resp))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.PersistentFlags().StringVarP(&cfgFile, "file", "f", "", "config file to bootstrap cluster(yaml format)")
}

//Setup ...
type Setup struct {
	User struct {
		Email    string `yaml:"email"`
		Password string `yaml:"password"`
	} `yaml:"user"`
	InternalDashboardLocation string `yaml:"internal_dashboard_location"`
	Tiller                    bool   `yaml:"tiller"`
	NetSettings               struct {
		ClusterCidr           string `yaml:"cluster_cidr"`
		ClusterCidrLowerBound string `yaml:"cluster_cidr_lower_bound"`
		ClusterCidrUpper      string `yaml:"cluster_cidr_upper"`
		NodeAllocationSize    int    `yaml:"node_allocation_size"`
		ServicesCidr          string `yaml:"services_cidr"`
		APIIPAddress          string `yaml:"api_ip_address"`
		DNSIPAddress          string `yaml:"dns_ip_address"`
	} `yaml:"net-settings"`
	Proxy struct {
		Enabled            bool   `yaml:"enabled"`
		HTTPProxy          string `yaml:"http_proxy"`
		HTTPSProxy         string `yaml:"https_proxy"`
		NoProxy            string `yaml:"no_proxy"`
		UseProxySystemwide string `yaml:"use_proxy_systemwide"`
	} `yaml:"proxy"`
	SuseRegistryMirror struct {
		Enabled            bool   `yaml:"enabled"`
		URL                string `yaml:"url"`
		Certificate        bool   `yaml:"certificate"`
		CertificateContent string `yaml:"certificate_content"`
	} `yaml:"suse_registry_mirror"`
	ContainerRuntime      string `yaml:"container_runtime"`
	SystemWideCertificate struct {
		Enabled            bool   `yaml:"enabled"`
		Name               string `yaml:"name"`
		CertificateContent string `yaml:"certificate_content"`
	} `yaml:"system_wide_certificate"`
	ExternalKubernetesAPIFqdn string `yaml:"external_kubernetes_api_fqdn"`
	ExternalDashboardFqdn     string `yaml:"external_dashboard_fqdn"`
}
