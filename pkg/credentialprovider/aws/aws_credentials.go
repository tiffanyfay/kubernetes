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
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"k8s.io/kubernetes/pkg/version"
)

// init registers a credential provider for each registryURLTemplate and creates
// an ECR token getter factory with a new cache to store token getters
func init() {
	credentialprovider.RegisterCredentialProvider("amazon-ecr",
		newECRProvider(&ecrTokenGetterFactory{cache: make(map[string]tokenGetter)}))
}

// ecrProvider is a DockerConfigProvider that gets and refreshes tokens
// from AWS to access ECR.
type ecrProvider struct {
	cache         cache.Store
	getterFactory tokenGetterFactory
}

var _ credentialprovider.DockerConfigProvider = &ecrProvider{}

func newECRProvider(getterFactory tokenGetterFactory) *ecrProvider {
	return &ecrProvider{
		cache:         cache.NewExpirationStore(stringKeyFunc, &ecrExpirationPolicy{}),
		getterFactory: getterFactory,
	}
}

// Enabled implements DockerConfigProvider.Enabled. Enabled is true if AWS
// credentials are found.
func (p *ecrProvider) Enabled() bool {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		klog.Errorf("while validating AWS credentials %v", err)
		return false
	}
	if _, err := sess.Config.Credentials.Get(); err != nil {
		klog.Errorf("while getting AWS credentials %v", err)
		return false
	}
	return true
}

// LazyProvide is lazy
// TODO: PR to remove LazyProvide
func (p *ecrProvider) LazyProvide(repoToPull string) *credentialprovider.DockerConfigEntry {
	return nil
}

// Provide returns a DockerConfig with credentials from the cache if they are
// found, or from ECR
func (p *ecrProvider) Provide(repoToPull string) credentialprovider.DockerConfig {
	parsed, err := parseRepoURL(repoToPull)
	if err != nil {
		klog.Errorf("while parsing repository URL %v", err)
		return credentialprovider.DockerConfig{}
	}
	if cfg, exists := p.getFromCache(parsed); exists {
		return cfg
	}
	return p.getFromECR(parsed)
}

// getFromCache attempts to get credentials from the cache
func (p *ecrProvider) getFromCache(parsed *parsedURL) (credentialprovider.DockerConfig, bool) {
	klog.V(3).Infof("Checking cache for credentials for %v", parsed.registry)
	cfg := credentialprovider.DockerConfig{}

	obj, exists, err := p.cache.GetByKey(parsed.registry)
	if err != nil {
		klog.V(3).Infof("unable to get credentials from cache for %v %v", parsed.registry, err)
		return cfg, exists
	}
	if exists {
		entry := obj.(*cacheEntry)
		cfg[entry.registry] = entry.credentials
	}
	return cfg, exists
}

// getFromECR gets credentials from ECR since they are not in the cache
func (p *ecrProvider) getFromECR(parsed *parsedURL) credentialprovider.DockerConfig {
	klog.V(3).Infof("Getting credentials from ECR for %v", parsed.registry)
	cfg := credentialprovider.DockerConfig{}
	getter, err := p.getterFactory.GetTokenGetterForRegion(parsed.region)
	if err != nil {
		return cfg
	}
	params := &ecr.GetAuthorizationTokenInput{RegistryIds: []*string{aws.String(parsed.registryID)}}
	output, err := getter.GetAuthorizationToken(params)
	if err != nil {
		klog.Errorf("while requesting ECR authorization token %v", err)
		return cfg
	}
	if output == nil {
		klog.Errorf("Got back no ECR token")
		return cfg
	}
	if len(output.AuthorizationData) == 0 {
		klog.Errorf("Got back no ECR authorization data")
		return cfg
	}
	data := output.AuthorizationData[0]
	if data.AuthorizationToken == nil {
		klog.Errorf("Got back no authorization token")
		return cfg
	}
	if data.ProxyEndpoint == nil {
		klog.Errorf("Got back no proxy endpoint")
		return cfg
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.StringValue(data.AuthorizationToken))
	if err != nil {
		klog.Errorf("while decoding token for endpoint %v %v", data.ProxyEndpoint, err)
		return cfg
	}
	parts := strings.SplitN(string(decodedToken), ":", 2)
	user := parts[0]
	password := parts[1]
	creds := credentialprovider.DockerConfigEntry{
		Username: user,
		Password: password,
		// ECR doesn't care and Docker is about to obsolete it
		Email: "not@val.id",
	}
	entry := &cacheEntry{
		expiresAt:   *data.ExpiresAt,
		credentials: creds,
		registry:    parsed.registry,
	}
	if err := p.cache.Add(entry); err != nil {
		klog.Errorf("while adding entry to cache %v", err)
		return cfg
	}
	cfg[entry.registry] = entry.credentials
	return cfg
}

type parsedURL struct {
	registryID string
	region     string
	registry   string
}

// parseRepoURL parses and splits the registry URL into the registry ID,
// region, and registry.
// <registryID>.dkr.ecr.<region>.amazonaws.com
// <registryID>.dkr.ecr.<region>.amazonaws.com.cn
func parseRepoURL(repoToPull string) (*parsedURL, error) {
	parsed, err := url.Parse("https://" + repoToPull)
	if err != nil {
		klog.Errorf("unable to parse repository URL %v", err)
		return nil, err
	}
	splitURL := strings.Split(parsed.Host, ".")
	if len(splitURL) < 4 || splitURL[2] != "ecr" || splitURL[4] != "amazonaws" {
		return nil, fmt.Errorf("%s is not a valid ECR repository URL", parsed.Host)
	}
	return &parsedURL{
		registryID: splitURL[0],
		region:     splitURL[3],
		registry:   parsed.Host,
	}, nil
}

// tokenGetter is for testing purposes
type tokenGetter interface {
	GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error)
}

// tokenGetterFactory is for testing purposes
type tokenGetterFactory interface {
	GetTokenGetterForRegion(string) (tokenGetter, error)
}

// ecrTokenGetterFactory stores a token getter per region
type ecrTokenGetterFactory struct {
	cache map[string]tokenGetter
}

// awsHandlerLogger is a handler that logs all AWS SDK requests
// Copied from pkg/cloudprovider/providers/aws/log_handler.go
func awsHandlerLogger(req *request.Request) {
	service := req.ClientInfo.ServiceName
	region := req.Config.Region

	name := "?"
	if req.Operation != nil {
		name = req.Operation.Name
	}

	klog.V(3).Infof("AWS request: %s:%s in %s", service, name, *region)
}

func newECRTokenGetter(region string) (tokenGetter, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		return nil, err
	}
	getter := &ecrTokenGetter{svc: ecr.New(sess)}
	getter.svc.Handlers.Build.PushFrontNamed(request.NamedHandler{
		Name: "k8s/user-agent",
		Fn:   request.MakeAddToUserAgentHandler("kubernetes", version.Get().String()),
	})
	getter.svc.Handlers.Sign.PushFrontNamed(request.NamedHandler{
		Name: "k8s/logger",
		Fn:   awsHandlerLogger,
	})
	return getter, nil
}

// GetTokenGetterForRegion gets the token getter for the requested region. If it
// doesn't exist, it creates a new ECR token getter
func (f *ecrTokenGetterFactory) GetTokenGetterForRegion(region string) (tokenGetter, error) {
	if getter, ok := f.cache[region]; ok {
		return getter, nil
	}
	getter, err := newECRTokenGetter(region)
	if err != nil {
		klog.Errorf("while getting creating token getter for region %v %v", region, err)
		return nil, err
	}
	f.cache[region] = getter
	return f.cache[region], nil
}

// The canonical implementation
type ecrTokenGetter struct {
	svc *ecr.ECR
}

// GetAuthorizationToken gets the ECR authorization token using the ECR API
func (p *ecrTokenGetter) GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error) {
	return p.svc.GetAuthorizationToken(input)
}

type cacheEntry struct {
	expiresAt   time.Time
	credentials credentialprovider.DockerConfigEntry
	registry    string
}

// ecrExpirationPolicy implements ExpirationPolicy from client-go.
type ecrExpirationPolicy struct{}

// stringKeyFunc returns the cache key as a string
func stringKeyFunc(obj interface{}) (string, error) {
	key := obj.(*cacheEntry).registry
	return key, nil
}

// IsExpired checks if the ECR credentials are expired. Credentials expire at
// 1/2 of their original requested window.
func (p *ecrExpirationPolicy) IsExpired(entry *cache.TimestampedEntry) bool {
	ecrExpiresAt := entry.Obj.(*cacheEntry).expiresAt
	validWindow := ecrExpiresAt.Sub(entry.Timestamp)
	expirationTime := ecrExpiresAt.Add(-1 * validWindow / time.Duration(2))
	return expirationTime.Before(time.Now())
}
