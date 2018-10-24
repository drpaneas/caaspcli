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
	"errors"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var (
	email, password string
)

// createUserCmd represents the createUser command
var createUserCmd = &cobra.Command{
	Use:   "create-user",
	Short: "creates a user",
	Args:  validateRootArgs,
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := createUser(email, password)
		if err != nil {
			return err
		}
		return nil
	},
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		if len(args) == 1 && args[0] == "help" {
			return nil
		}
		return errors.New("requires at least two args to execute")
	}
	email = args[0]
	password = args[1]
	return nil
}

func init() {
	setupCmd.AddCommand(createUserCmd)
}

func createUser(email string, password string) error {
	createUserCmd := exec.Command("/bin/sh", "-c", "'docker exec -it $(docker ps -q -f 'name=k8s_velum-dashboard') entrypoint.sh bash -c \"rake velum:create_user['"+email+"','"+password+"']\"'")
	fmt.Printf("%s", createUserCmd.Args)
	b, err := createUserCmd.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Printf("%s", string(b))
	return nil
}
