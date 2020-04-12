package cachedstscreds

import (
	"fmt"
	"os"
	"time"

	// "github.com/aws/aws-sdk-go/aws"
	// "github.com/aws/aws-sdk-go/aws/awserr"
	// "github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	// "github.com/aws/aws-sdk-go/aws/request"
	// "github.com/aws/aws-sdk-go/internal/sdkrand"
	"github.com/aws/aws-sdk-go/service/sts"
)

// ProviderName provides a name of CachedAssumeRoleProvider
const ProviderName = "CachedAssumeRoleProvider"

// DefaultDuration is the default amount of time in minutes that the credentials
// will be valid for.
var DefaultDuration = time.Duration(15) * time.Minute

// CachedAssumeRoleProvider retrieves temporary credentials from the STS service, and
// keeps track of their expiration time.
//
// This credential provider will be used by the SDKs default credential change
// when shared configuration is enabled, and the shared config or shared credentials
// file configure assume role. See Session docs for how to do this.
//
// AssumeRoleProvider does not provide any synchronization and it is not safe
// to share this value across multiple Credentials, Sessions, or service clients
// without also sharing the same Credentials instance.
type CachedAssumeRoleProvider struct {
	credentials.Expiry

	// Source profile role ARN to assume. This role's credentials are then used
	// to assume the roles in the other accounts.
	SourceProfileRoleARN string

	// The role ARN to assume from the requested profile
	RoleARN string

	// Session name, if you wish to reuse the credentials elsewhere.
	RoleSessionName string

	// Optional, you can pass tag key-value pairs to your session. These tags are called session tags.
	Tags []*sts.Tag
}

func (p *CachedAssumeRoleProvider) Retrieve() (Value credentials.Value, err error) {
	// Create session in source profile

	// Get session token with MFA
	// Cache Result
	// Assume role in other accounts

	return Value{
		AccessKeyID:     id,
		SecretAccessKey: secret,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		ProviderName:    EnvProviderName,
	}, nil
}

// Returns whether or not the source profile's session has expired
func (p *CachedAssumeRoleProvider) IsExpired() bool {
	return false
}
