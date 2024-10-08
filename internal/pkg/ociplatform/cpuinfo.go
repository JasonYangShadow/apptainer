// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package ociplatform

import (
	"runtime"
	"sync"

	"github.com/apptainer/apptainer/pkg/sylog"
)

// Present the ARM instruction set architecture, eg: v7, v8
// Don't use this value directly; call cpuVariant() instead.
var cpuVariantValue string

var cpuVariantOnce sync.Once

func CPUVariant() string {
	cpuVariantOnce.Do(func() {
		if isArmArch(runtime.GOARCH) {
			var err error
			cpuVariantValue, err = getCPUVariant()
			if err != nil {
				sylog.Errorf("Error getCPUVariant for OS %s: %v", runtime.GOOS, err)
			}
		}
	})
	return cpuVariantValue
}
