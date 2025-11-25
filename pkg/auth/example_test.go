package auth_test

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/stackitcloud/stackit-cli/internal/pkg/print"
	"github.com/stackitcloud/stackit-cli/pkg/auth"
)

// Example_providerAuthFlow demonstrates how to use ProviderAuthFlow
// in the STACKIT Terraform Provider or SDK.
func Example_providerAuthFlow() {
	// Create a printer (required for debug output)
	cmd := &cobra.Command{}
	printer := &print.Printer{Cmd: cmd}

	// Get the authentication RoundTripper
	authFlow, err := auth.ProviderAuthFlow(printer)
	if err != nil {
		// User needs to run: stackit auth provider login
		fmt.Println("Not authenticated")
		return
	}

	// Create HTTP client with authentication
	client := &http.Client{
		Transport: authFlow,
	}

	// All requests are automatically authenticated and tokens are refreshed as needed
	_ = client
	fmt.Println("Authenticated")
}

// Example_getProviderAccessToken demonstrates how to get an access token directly.
func Example_getProviderAccessToken() {
	cmd := &cobra.Command{}
	printer := &print.Printer{Cmd: cmd}

	// Get a valid access token (automatically refreshed if needed)
	token, err := auth.GetProviderAccessToken(printer)
	if err != nil {
		fmt.Println("Not authenticated")
		return
	}

	// Use token in Authorization header
	fmt.Printf("Token length: %d\n", len(token))
}

// Example_isProviderAuthenticated demonstrates how to check authentication status.
func Example_isProviderAuthenticated() {
	// Check if user has authenticated
	if !auth.IsProviderAuthenticated() {
		fmt.Println("Please run: stackit auth provider login")
		return
	}

	fmt.Println("User is authenticated")
}

// Example_terraformProviderIntegration shows a complete example of how the
// STACKIT Terraform Provider would integrate with CLI authentication.
func Example_terraformProviderIntegration() {
	cmd := &cobra.Command{}
	printer := &print.Printer{Cmd: cmd}

	// Check authentication first
	if !auth.IsProviderAuthenticated() {
		fmt.Println("Not authenticated: run 'stackit auth provider login'")
		return
	}

	// Get authentication flow
	authFlow, err := auth.ProviderAuthFlow(printer)
	if err != nil {
		fmt.Printf("Failed to get auth: %v\n", err)
		return
	}

	// Create HTTP client
	client := &http.Client{
		Transport: authFlow,
	}

	// Use client for API calls - authentication and token refresh are automatic
	_ = client

	fmt.Println("Provider configured with CLI authentication")
}
