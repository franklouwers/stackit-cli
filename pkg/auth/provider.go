// Package auth provides authentication functionality for external integrations,
// particularly for the STACKIT Terraform Provider and SDK.
//
// This package enables external tools to use credentials stored by the STACKIT CLI
// without requiring users to create service accounts for local development.
package auth

import (
	"net/http"

	internalAuth "github.com/stackitcloud/stackit-cli/internal/pkg/auth"
	"github.com/stackitcloud/stackit-cli/internal/pkg/print"
)

// ProviderAuthFlow returns an http.RoundTripper that authenticates using
// provider credentials stored by `stackit auth provider login`.
//
// The returned RoundTripper:
// - Adds Authorization header to all requests
// - Automatically refreshes expired tokens
// - Writes refreshed tokens back to storage (bidirectional sync)
// - Re-authenticates if refresh fails (prompts user to login again)
//
// Example usage in Terraform Provider:
//
//	import "github.com/stackitcloud/stackit-cli/pkg/auth"
//
//	printer := // ... create printer
//	authFlow, err := auth.ProviderAuthFlow(printer)
//	if err != nil {
//	    return fmt.Errorf("failed to get provider auth: %w", err)
//	}
//
//	client := &http.Client{
//	    Transport: authFlow,
//	}
func ProviderAuthFlow(p *print.Printer) (http.RoundTripper, error) {
	// Check if provider credentials exist
	flow, err := internalAuth.GetAuthFlowWithContext(internalAuth.StorageContextProvider)
	if err != nil {
		return nil, &NotAuthenticatedError{}
	}
	if flow == "" {
		return nil, &NotAuthenticatedError{}
	}

	// Return the round tripper configured for provider context
	return internalAuth.UserTokenFlowWithContext(p, internalAuth.StorageContextProvider), nil
}

// GetProviderAccessToken returns a valid access token for the provider context.
// It automatically refreshes the token if expired and writes the refreshed token
// back to storage.
//
// Returns NotAuthenticatedError if no provider credentials are found.
//
// Example usage:
//
//	import "github.com/stackitcloud/stackit-cli/pkg/auth"
//
//	printer := // ... create printer
//	token, err := auth.GetProviderAccessToken(printer)
//	if err != nil {
//	    return fmt.Errorf("failed to get access token: %w", err)
//	}
func GetProviderAccessToken(p *print.Printer) (string, error) {
	// Check if provider credentials exist
	flow, err := internalAuth.GetAuthFlowWithContext(internalAuth.StorageContextProvider)
	if err != nil {
		return "", &NotAuthenticatedError{}
	}
	if flow == "" {
		return "", &NotAuthenticatedError{}
	}

	// Get valid access token (with automatic refresh)
	token, err := internalAuth.GetValidAccessTokenWithContext(p, internalAuth.StorageContextProvider)
	if err != nil {
		return "", err
	}

	return token, nil
}

// IsProviderAuthenticated checks if provider credentials exist.
// Returns true if the user has run `stackit auth provider login`.
func IsProviderAuthenticated() bool {
	flow, err := internalAuth.GetAuthFlowWithContext(internalAuth.StorageContextProvider)
	return err == nil && flow != ""
}

// NotAuthenticatedError indicates that no provider credentials are available.
// Users should run `stackit auth provider login` to authenticate.
type NotAuthenticatedError struct{}

func (e *NotAuthenticatedError) Error() string {
	return "not authenticated with STACKIT CLI provider credentials: please run 'stackit auth provider login'"
}
