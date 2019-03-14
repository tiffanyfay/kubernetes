/*
Copyright 2014 The Kubernetes Authors.

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

package credentials

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"

	"k8s.io/kubernetes/pkg/credentialprovider"
)

const user = "foo"
const password = "1234567890abcdef"
const email = "not@val.id"

// Mock implementation
type testTokenGetter struct {
	user              string
	password          string
	endpoint          string
	randomizePassword bool
}

type testTokenGetterFactory struct {
	getter tokenGetter
}

func (f *testTokenGetterFactory) GetTokenGetterForRegion(region string) tokenGetter {
	return f.getter
}

func (p *testTokenGetter) GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error) {
	if p.randomizePassword {
		rand.Seed(int64(time.Now().Nanosecond()))
		p.password = strconv.Itoa(rand.Int())
	}
	expiration := time.Now().Add(1 * time.Hour)
	// expiration := time.Now().Add(5 * time.Second) //for testing with the cache expiring
	creds := []byte(fmt.Sprintf("%s:%s", p.user, p.password))
	data := &ecr.AuthorizationData{
		AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString(creds)),
		ExpiresAt:          &expiration,
		ProxyEndpoint:      aws.String(p.endpoint),
	}
	output := &ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []*ecr.AuthorizationData{data},
	}
	return output, nil //p.svc.GetAuthorizationToken(input)
}

func TestParseRepoURLPass(t *testing.T) {
	registryID := "123456789012"
	region := "lala-land-1"
	registry := "123456789012.dkr.ecr.lala-land-1.amazonaws.com"
	repoToPull := path.Join(registry, "foo/bar")
	parsedURL, err := parseRepoURL(repoToPull)

	if err != nil {
		t.Errorf("Could not parse URL: %s, err: %v", repoToPull, err)
	}
	if registryID != parsedURL.registryID {
		t.Errorf("Unexpected registryID value, want: %s, got: %s", registryID, parsedURL.registryID)
	}
	if region != parsedURL.region {
		t.Errorf("Unexpected region value, want: %s, got: %s", region, parsedURL.region)
	}
	if registry != parsedURL.registry {
		t.Errorf("Unexpected registry value, want: %s, got: %s", registry, parsedURL.registry)
	}
}

func TestParseRepoURLFail(t *testing.T) {
	registry := "123456789012.amazonaws.com"
	repoToPull := path.Join(registry, "foo/bar")
	parsedURL, err := parseRepoURL(repoToPull)
	expectedErr := "repository URL 123456789012.amazonaws.com improperly formatted"

	if err == nil {
		t.Errorf("Should fail to parse URL %s", repoToPull)
	}
	if err.Error() != expectedErr {
		t.Errorf("Unexpected error, want: %s, got: %v", expectedErr, err)
	}
	if parsedURL != nil {
		t.Errorf("Expected parsedURL to be nil")
	}
}

func TestECRProvide(t *testing.T) {
	registry := "123456789012.dkr.ecr.lala-land-1.amazonaws.com"
	otherRegistries := []string{
		"123456789012.dkr.ecr.cn-foo-1.amazonaws.com.cn",
		"private.registry.com",
		"gcr.io",
	}
	image := "foo/bar"
	repoToPull := path.Join(registry, image)
	p := newECRProvider(registryURLTemplateStandard,
		&testTokenGetterFactory{
			getter: &testTokenGetter{
				user:     user,
				password: password,
				endpoint: registry,
			},
		})
	keyring := &credentialprovider.BasicDockerKeyring{}
	keyring.Add(p.Provide(repoToPull))

	// Verify that we get the expected username/password combo for
	// an ECR image name.
	creds, ok := keyring.Lookup(repoToPull)
	if !ok {
		t.Errorf("Didn't find expected URL: %s", repoToPull)
		return
	}
	if len(creds) > 1 {
		t.Errorf("Got more hits than expected: %s", creds)
	}
	cred := creds[0]
	if user != cred.Username {
		t.Errorf("Unexpected username value, want: %s, got: %s", user, cred.Username)
	}
	if password != creds[0].Password {
		t.Errorf("Unexpected password value, want: %s, got: %s", password, cred.Password)
	}
	if email != creds[0].Email {
		t.Errorf("Unexpected email value, want: %s, got: %s", email, cred.Email)
	}

	// Verify that we get an error for other images.
	for _, otherRegistry := range otherRegistries {
		repoToPull = path.Join(otherRegistry, image)
		creds, ok = keyring.Lookup(repoToPull)
		if ok {
			t.Errorf("Unexpectedly found image: %s", repoToPull)
			return
		}
	}
}

func TestECRProvideCached(t *testing.T) {
	registry := "123456789012.dkr.ecr.lala-land-1.amazonaws.com"
	image1 := "foo/bar"
	image2 := "bar/baz"
	p := newECRProvider(registryURLTemplateStandard,
		&testTokenGetterFactory{
			getter: &testTokenGetter{
				user:              user,
				password:          password,
				endpoint:          registry,
				randomizePassword: true,
			},
		})
	repoToPull1 := path.Join(registry, image1)
	repoToPull2 := path.Join(registry, image2)
	keyring := &credentialprovider.BasicDockerKeyring{}
	keyring.Add(p.Provide(repoToPull1))
	// time.Sleep(6 * time.Second) //for testing with the cache expiring
	keyring.Add(p.Provide(repoToPull2))
	// Verify that we get the credentials from the
	// cache the second time
	creds1, ok := keyring.Lookup(repoToPull1)
	if !ok {
		t.Errorf("Didn't find expected URL: %s", repoToPull1)
		return
	}
	if len(creds1) != 2 {
		t.Errorf("Got more hits than expected: %s", creds1)
	}

	if creds1[0].Password != creds1[1].Password {
		t.Errorf("cached credentials do not match")
	}

	creds2, ok := keyring.Lookup(repoToPull2)
	if !ok {
		t.Errorf("Didn't find expected URL: %s", repoToPull1)
		return
	}
	if len(creds2) != 2 {
		t.Errorf("Got more hits than expected: %s", creds2)
	}

	if creds2[0].Password != creds2[1].Password {
		t.Errorf("cached credentials do not match")
	}
	if creds1[0].Password != creds2[0].Password {
		t.Errorf("cached credentials do not match")
	}
}

func TestChinaECRProvide(t *testing.T) {
	registry := "123456789012.dkr.ecr.cn-foo-1.amazonaws.com.cn"
	otherRegistries := []string{
		"123456789012.dkr.ecr.lala-land-1.amazonaws.com",
		"private.registry.com",
		"gcr.io",
	}
	image := "foo/bar"
	repoToPull := path.Join(registry, image)
	p := newECRProvider(registryURLTemplateChina,
		&testTokenGetterFactory{
			getter: &testTokenGetter{
				user:     user,
				password: password,
				endpoint: registry,
			},
		})
	keyring := &credentialprovider.BasicDockerKeyring{}
	keyring.Add(p.Provide(repoToPull))
	// Verify that we get the expected username/password combo for
	// an ECR image name.
	creds, ok := keyring.Lookup(repoToPull)
	if !ok {
		t.Errorf("Didn't find expected URL: %s", repoToPull)
		return
	}
	if len(creds) > 1 {
		t.Errorf("Got more hits than expected: %s", creds)
	}
	cred := creds[0]
	if user != cred.Username {
		t.Errorf("Unexpected username value, want: %s, got: %s", user, cred.Username)
	}
	if password != cred.Password {
		t.Errorf("Unexpected password value, want: %s, got: %s", password, cred.Password)
	}
	if email != cred.Email {
		t.Errorf("Unexpected email value, want: %s, got: %s", email, cred.Email)
	}

	// Verify that we get an error for other images.
	for _, otherRegistry := range otherRegistries {
		repoToPull = path.Join(otherRegistry, image)
		creds, ok = keyring.Lookup(repoToPull)
		if ok {
			t.Errorf("Unexpectedly found image: %s", repoToPull)
			return
		}
	}
}

func TestChinaECRProvideCached(t *testing.T) {
	registry := "123456789012.dkr.ecr.cn-foo-1.amazonaws.com.cn"
	image := "foo/bar"
	p := newECRProvider(registryURLTemplateChina,
		&testTokenGetterFactory{
			getter: &testTokenGetter{
				user:              user,
				password:          password,
				endpoint:          registry,
				randomizePassword: true,
			},
		})
	repoToPull := path.Join(registry, image)
	keyring := &credentialprovider.BasicDockerKeyring{}
	keyring.Add(p.Provide(repoToPull))
	// time.Sleep(6 * time.Second) //for testing with the cache expiring
	keyring.Add(p.Provide(repoToPull))
	// Verify that we get the credentials from the
	// cache the second time
	creds, ok := keyring.Lookup(repoToPull)
	if !ok {
		t.Errorf("Didn't find expected URL: %s", repoToPull)
		return
	}
	if len(creds) != 2 {
		t.Errorf("Got more hits than expected: %s", creds)
	}

	if creds[0].Password != creds[1].Password {
		t.Errorf("cached credentials do not match")
	}
}
