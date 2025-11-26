package auth

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	internalAuth "github.com/stackitcloud/stackit-cli/internal/pkg/auth"
	"github.com/stackitcloud/stackit-cli/internal/pkg/print"
	"github.com/zalando/go-keyring"
)

func TestProviderAuthFlow_NotAuthenticated(t *testing.T) {
	keyring.MockInit()

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	p := &print.Printer{Cmd: cmd}

	// Ensure no provider credentials exist
	_ = internalAuth.LogoutUserWithContext(internalAuth.StorageContextProvider)

	// Should return NotAuthenticatedError
	_, err := ProviderAuthFlow(p)
	if err == nil {
		t.Fatal("Expected error when not authenticated, got nil")
	}

	notAuthErr, ok := err.(*NotAuthenticatedError)
	if !ok {
		t.Errorf("Expected NotAuthenticatedError, got: %v", err)
	} else if notAuthErr.Error() == "" {
		t.Error("NotAuthenticatedError should have non-empty message")
	}
}

func TestGetProviderAccessToken_NotAuthenticated(t *testing.T) {
	keyring.MockInit()

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	p := &print.Printer{Cmd: cmd}

	// Ensure no provider credentials exist
	_ = internalAuth.LogoutUserWithContext(internalAuth.StorageContextProvider)

	// Should return NotAuthenticatedError
	_, err := GetProviderAccessToken(p)
	if err == nil {
		t.Fatal("Expected error when not authenticated, got nil")
	}

	if _, ok := err.(*NotAuthenticatedError); !ok {
		t.Errorf("Expected NotAuthenticatedError, got: %v", err)
	}
}

func TestIsProviderAuthenticated(t *testing.T) {
	keyring.MockInit()

	// Ensure no provider credentials exist
	_ = internalAuth.LogoutUserWithContext(internalAuth.StorageContextProvider)

	// Should return false when not authenticated
	if IsProviderAuthenticated() {
		t.Error("Expected IsProviderAuthenticated to return false, got true")
	}

	// Login to provider context
	err := internalAuth.LoginUserWithContext(
		internalAuth.StorageContextProvider,
		"test@example.com",
		"test-access-token",
		"test-refresh-token",
		"9999999999",
	)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	err = internalAuth.SetAuthFlowWithContext(internalAuth.StorageContextProvider, internalAuth.AUTH_FLOW_USER_TOKEN)
	if err != nil {
		t.Fatalf("Failed to set auth flow: %v", err)
	}

	// Should return true when authenticated
	if !IsProviderAuthenticated() {
		t.Error("Expected IsProviderAuthenticated to return true, got false")
	}

	// Cleanup
	_ = internalAuth.LogoutUserWithContext(internalAuth.StorageContextProvider)
}

func TestProviderAuthFlow_Authenticated(t *testing.T) {
	keyring.MockInit()

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	p := &print.Printer{Cmd: cmd}

	// Login to provider context
	err := internalAuth.LoginUserWithContext(
		internalAuth.StorageContextProvider,
		"test@example.com",
		"test-access-token",
		"test-refresh-token",
		"9999999999",
	)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	err = internalAuth.SetAuthFlowWithContext(internalAuth.StorageContextProvider, internalAuth.AUTH_FLOW_USER_TOKEN)
	if err != nil {
		t.Fatalf("Failed to set auth flow: %v", err)
	}

	// Should successfully return RoundTripper
	roundTripper, err := ProviderAuthFlow(p)
	if err != nil {
		t.Errorf("Expected no error when authenticated, got: %v", err)
	}

	if roundTripper == nil {
		t.Error("Expected non-nil RoundTripper, got nil")
	}

	// Cleanup
	_ = internalAuth.LogoutUserWithContext(internalAuth.StorageContextProvider)
}
