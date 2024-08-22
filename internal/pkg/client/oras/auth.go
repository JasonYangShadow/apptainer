// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Control Command Inc. All rights reserved.
// Copyright (c) 2020-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.
//
// The following code is adapted from:
//
//	https://github.com/google/go-containerregistry/blob/v0.15.2/pkg/authn/keychain.go
//
// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oras

import (
	"errors"
	"io/fs"
	"os"
	"sync"

	"github.com/apptainer/apptainer/pkg/syfs"
	"github.com/apptainer/apptainer/pkg/sylog"
	ocitypes "github.com/containers/image/v5/types"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type apptainerKeychain struct {
	mu          sync.Mutex
	reqAuthFile string
}

// Resolve implements Keychain.
func (sk *apptainerKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	authFile := syfs.DockerConf()
	f, err := os.Open(authFile)
	if os.IsNotExist(err) {
		fallbackPath := syfs.FallbackDockerConf()
		sylog.Debugf("Auth file %q does not exist, fallback to %s", authFile, fallbackPath)
		f, err = os.Open(fallbackPath)
		if os.IsNotExist(err) {
			sylog.Debugf("Auth file %q does not exist, using anonymous auth", authFile)
			return authn.Anonymous, nil
		}
	}
	if errors.Is(err, fs.ErrPermission) {
		sylog.Warningf("Reading auth file %q has error: %s", authFile, fs.ErrPermission.Error())
		return authn.Anonymous, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cf, err := config.LoadFromReader(f)
	if err != nil {
		return nil, err
	}

	// See:
	// https://github.com/google/ko/issues/90
	// https://github.com/moby/moby/blob/fc01c2b481097a6057bec3cd1ab2d7b4488c50c4/registry/config.go#L397-L404
	var cfg, empty types.AuthConfig
	for _, key := range []string{
		target.String(),
		target.RegistryStr(),
	} {
		if key == name.DefaultRegistry {
			key = authn.DefaultAuthKey
		}

		cfg, err = cf.GetAuthConfig(key)
		if err != nil {
			return nil, err
		}
		// cf.GetAuthConfig automatically sets the ServerAddress attribute. Since
		// we don't make use of it, clear the value for a proper "is-empty" test.
		// See: https://github.com/google/go-containerregistry/issues/1510
		cfg.ServerAddress = ""
		if cfg != empty {
			break
		}
	}

	if cfg == empty {
		return authn.Anonymous, nil
	}

	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}

func AuthOptn(ociAuth *ocitypes.DockerAuthConfig, reqAuthFile string) remote.Option {
	// By default we use auth from ~/.apptainer/docker-config.json
	authOptn := remote.WithAuthFromKeychain(&apptainerKeychain{reqAuthFile: reqAuthFile})

	// If explicit credentials in ociAuth were passed in, use those instead.
	if ociAuth != nil {
		auth := authn.FromConfig(authn.AuthConfig{
			Username:      ociAuth.Username,
			Password:      ociAuth.Password,
			IdentityToken: ociAuth.IdentityToken,
		})
		authOptn = remote.WithAuth(auth)
	}
	return authOptn
}
