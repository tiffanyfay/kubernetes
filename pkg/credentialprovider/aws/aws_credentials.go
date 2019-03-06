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
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"k8s.io/klog"

	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"k8s.io/kubernetes/pkg/version"
)

const registryURLTemplateStandard = "*.dkr.ecr.*.amazonaws.com"
const registryURLTemplateChina = "*.dkr.ecr.*.amazonaws.com.cn"

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

/*PARSE*/
type parsedURL struct {
	registryID string
	region     string
	host       string
}

// url.Parse require a scheme, but ours don't have schemes.  Adding a
// scheme to make url.Parse happy, then clear out the resulting scheme.
func parseSchemelessURL(schemelessURL string) (*url.URL, error) {
	parsed, err := url.Parse("https://" + schemelessURL)
	if err != nil {
		return nil, err
	}
	// clear out the resulting scheme
	parsed.Scheme = ""
	return parsed, nil
}

func splitSchemelessURL(repoToPull string) (*parsedURL, error) {
	parsed, err := parseSchemelessURL(repoToPull)
	if err != nil {
		klog.Errorf("unable to parse registry URL %v", err)
		return nil, err
	}
	splitURL := strings.Split(parsed.Host, ".")
	if len(splitURL) < 4 {
		return nil, errors.New("registry URL can't be split")
	}
	return &parsedURL{
		registryID: splitURL[0],
		region:     splitURL[3],
		host:       parsed.Host,
	}, nil
}

/* GETTER */
// An interface for testing purposes.
type tokenGetter interface {
	GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error)
}

// The canonical implementation
type ecrTokenGetter struct {
	svc *ecr.ECR
}

func (p *ecrTokenGetter) GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error) {
	return p.svc.GetAuthorizationToken(input)
}

func newGetter(region string) *ecrTokenGetter {
	getter := &ecrTokenGetter{svc: ecr.New(session.New(&aws.Config{
		Credentials: nil,
		Region:      aws.String(region),
	}))}
	getter.svc.Handlers.Build.PushFrontNamed(request.NamedHandler{
		Name: "k8s/user-agent",
		Fn:   request.MakeAddToUserAgentHandler("kubernetes", version.Get().String()),
	})
	getter.svc.Handlers.Sign.PushFrontNamed(request.NamedHandler{
		Name: "k8s/logger",
		Fn:   awsHandlerLogger,
	})
	return getter
}

/*GET CREDENTIALS*/
type cacheEntry struct {
	expiresAt   time.Time
	credentials credentialprovider.DockerConfigEntry
	host        string
}

// stringKeyFunc is a string as cache key function
func stringKeyFunc(obj interface{}) (string, error) {
	key := obj.(cacheEntry).host
	return key, nil
}

func (p *ecrProvider) getFromCache(parsed *parsedURL) (credentialprovider.DockerConfig, bool) {
	klog.Infof("Checking cache for credentials for %v", parsed.host)
	cfg := credentialprovider.DockerConfig{}
	obj, exists, err := p.cache.GetByKey(parsed.host)
	if err != nil {
		klog.Infof("unable to get credentials from cache for %v %v", parsed.host, err)
		return cfg, exists
	}
	if exists {
		entry := obj.(cacheEntry)
		if entry.expiresAt.After(time.Now()) {
			klog.Info("Credentials found in cache")
			cfg[entry.host] = entry.credentials
		} else {
			klog.Info("Credentials in cache are expired")
			// if entry is past the ECR expiration policy, remove item from cache
			if err := p.cache.Delete(obj); err != nil {
				klog.Errorf("while removing expired entry from cache %v", err)
			}
			exists = false
		}
	}
	return cfg, exists
}

func (p *ecrProvider) getFromECR(parsed *parsedURL) credentialprovider.DockerConfig {
	klog.Infof("Getting credentials from ECR for %v", parsed.host)
	cfg := credentialprovider.DockerConfig{}
	if p.getter == nil {
		p.getter = newGetter(parsed.region)
	}

	params := &ecr.GetAuthorizationTokenInput{RegistryIds: []*string{aws.String(parsed.registryID)}}
	output, err := p.getter.GetAuthorizationToken(params)
	if err != nil {
		klog.Errorf("while requesting ECR authorization token %v", err)
		return cfg
	}
	if output == nil {
		klog.Errorf("Got back no ECR token")
		return cfg
	}

	data := output.AuthorizationData[0]
	if data.ProxyEndpoint != nil &&
		data.AuthorizationToken != nil {
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
		entry := cacheEntry{
			expiresAt:   *data.ExpiresAt,
			credentials: creds,
			host:        parsed.host,
		}
		if err := p.cache.Add(entry); err != nil {
			klog.Errorf("while adding entry to cache %v", err)
			return cfg
		}
		cfg[entry.host] = entry.credentials
	}
	return cfg
}

/*PROVIDER*/
// ecrProvider is a DockerConfigProvider that gets and refreshes tokens
// from AWS to access ECR.
type ecrProvider struct {
	registryURLTemplate string
	cache               cache.Store
	getter              tokenGetter
}

var _ credentialprovider.DockerConfigProvider = &ecrProvider{}

// RegisterCredentialsProvider registers a credential provider for the specified region.
// It creates a lazy provider for each AWS region, in order to support
// cross-region ECR access. They have to be lazy because it's unlikely, but not
// impossible, that we'll use more than one.
// This should be called only if using the AWS cloud provider.
// This way, we avoid timeouts waiting for a non-existent provider.
func init() {
	credentialprovider.RegisterCredentialProvider("aws-ecr-partition-standard",
		newECRProvider(registryURLTemplateStandard, nil))

	credentialprovider.RegisterCredentialProvider("aws-ecr-partition-china",
		newECRProvider(registryURLTemplateChina, nil))
}

func newECRProvider(template string, getter tokenGetter) *ecrProvider {
	//make cache
	//key: repotoPull host only component. Don't want port, don't want repository v: ecrCache struct

	return &ecrProvider{
		registryURLTemplate: template,
		cache:               cache.NewTTLStore(stringKeyFunc, 1*time.Hour),
		getter:              getter,
	}
}

// Enabled implements DockerConfigProvider.Enabled for the AWS token-based implementation.
// For now, it gets activated only if AWS was chosen as the cloud provider.
// TODO: figure how to enable it manually for deployments that are not on AWS but still
// use ECR somehow?
func (p *ecrProvider) Enabled() bool {
	return true
}

// LazyProvide is lazy
func (p *ecrProvider) LazyProvide(repoToPull string) *credentialprovider.DockerConfigEntry {
	return nil
}

// Provide provides credentials from the cache if they are found, or from ECR
func (p *ecrProvider) Provide(repoToPull string) credentialprovider.DockerConfig {
	cfg := credentialprovider.DockerConfig{}

	parsed, err := splitSchemelessURL(repoToPull)
	if err != nil {
		klog.Errorf("unable to parse repo url %s %v", repoToPull, err)
		return cfg
	}
	cfg, exists := p.getFromCache(parsed)
	if !exists {
		return p.getFromECR(parsed)
	}
	return cfg
}
