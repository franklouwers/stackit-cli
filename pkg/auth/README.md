# STACKIT CLI Authentication Package

This package provides authentication functionality for external integrations with the STACKIT CLI, particularly for the STACKIT Terraform Provider and SDK.

## Overview

This package enables the STACKIT Terraform Provider and SDK to use credentials stored by the STACKIT CLI, eliminating the need for users to create service accounts for local development.

## Authentication Flow

1. **User authenticates via CLI**:
   ```bash
   stackit auth provider login
   ```
   This opens a browser for OAuth2 authentication and stores credentials.

2. **Terraform Provider/SDK uses stored credentials**:
   ```go
   import "github.com/stackitcloud/stackit-cli/pkg/auth"

   authFlow, err := auth.ProviderAuthFlow(printer)
   // Uses the credentials stored by CLI
   ```

3. **Automatic token refresh**:
   - Tokens expire after 15 minutes
   - The RoundTripper automatically refreshes expired tokens
   - Refreshed tokens are written back to CLI storage
   - Both CLI and Provider see updated tokens (bidirectional sync)

## Usage Examples

### Option 1: Using http.RoundTripper (Recommended)

This is the recommended approach as it handles token refresh automatically for every request:

```go
package main

import (
    "net/http"

    "github.com/stackitcloud/stackit-cli/pkg/auth"
    "github.com/stackitcloud/stackit-cli/internal/pkg/print"
)

func main() {
    // Create a printer (required for debug output)
    printer := print.NewPrinter()

    // Get the authentication RoundTripper
    authFlow, err := auth.ProviderAuthFlow(printer)
    if err != nil {
        // User needs to run: stackit auth provider login
        panic(err)
    }

    // Create HTTP client with authentication
    client := &http.Client{
        Transport: authFlow,
    }

    // All requests are automatically authenticated
    resp, err := client.Get("https://api.stackit.cloud/...")
}
```

### Option 2: Getting Access Token Directly

If you need the access token as a string (e.g., for custom HTTP clients):

```go
package main

import (
    "github.com/stackitcloud/stackit-cli/pkg/auth"
    "github.com/stackitcloud/stackit-cli/internal/pkg/print"
)

func main() {
    printer := print.NewPrinter()

    // Get a valid access token (automatically refreshed if needed)
    token, err := auth.GetProviderAccessToken(printer)
    if err != nil {
        panic(err)
    }

    // Use token in Authorization header
    req.Header.Set("Authorization", "Bearer " + token)
}
```

### Option 3: Checking Authentication Status

Check if the user is authenticated before attempting operations:

```go
package main

import (
    "fmt"

    "github.com/stackitcloud/stackit-cli/pkg/auth"
)

func main() {
    if !auth.IsProviderAuthenticated() {
        fmt.Println("Please authenticate: stackit auth provider login")
        return
    }

    // Proceed with authenticated operations
}
```

## Integration with STACKIT SDK

Example integration with the STACKIT SDK:

```go
package main

import (
    "github.com/stackitcloud/stackit-cli/pkg/auth"
    "github.com/stackitcloud/stackit-cli/internal/pkg/print"
    sdkConfig "github.com/stackitcloud/stackit-sdk-go/core/config"
)

func main() {
    printer := print.NewPrinter()

    // Get provider auth flow
    authFlow, err := auth.ProviderAuthFlow(printer)
    if err != nil {
        panic(err)
    }

    // Configure SDK with provider authentication
    cfg := sdkConfig.WithCustomAuth(authFlow)

    // Create SDK client
    // client := someSDKService.NewAPIClient(cfg)
}
```

## Error Handling

The package provides a `NotAuthenticatedError` when credentials are not found:

```go
authFlow, err := auth.ProviderAuthFlow(printer)
if err != nil {
    var notAuthErr *auth.NotAuthenticatedError
    if errors.As(err, &notAuthErr) {
        fmt.Println("Please run: stackit auth provider login")
        return
    }
    // Handle other errors
    panic(err)
}
```

## Storage Location

Provider credentials are stored separately from CLI credentials:

| Storage | Location |
|---------|----------|
| Keyring (macOS) | Keychain entry: `stackit-cli-provider` |
| Keyring (Windows) | Credential Manager: `stackit-cli-provider` |
| Keyring (Linux) | Secret Service: `stackit-cli-provider` |
| File Fallback | `~/.stackit/cli-provider-auth-storage.txt` (base64-encoded) |

## Token Refresh Behavior

- **Automatic refresh**: Tokens are checked on every HTTP request
- **Bidirectional sync**: Refreshed tokens are written back to storage
- **Concurrent safety**: CLI and Provider can be authenticated simultaneously with different accounts
- **Re-authentication**: If refresh fails, the user is prompted to login again

## Security Considerations

1. **Credential isolation**: Provider credentials are stored separately from CLI credentials
2. **Secure storage**: Primary storage uses system keyring (Keychain/Credential Manager/Secret Service)
3. **File fallback**: Falls back to base64-encoded file when keyring is unavailable
4. **Token rotation**: Both access and refresh tokens are rotated on each refresh

## API Reference

### Functions

#### `ProviderAuthFlow(p *print.Printer) (http.RoundTripper, error)`

Returns an `http.RoundTripper` that authenticates using provider credentials.

**Parameters:**
- `p`: Printer for debug output

**Returns:**
- `http.RoundTripper`: Transport that adds authentication to requests
- `error`: `NotAuthenticatedError` if no credentials found

---

#### `GetProviderAccessToken(p *print.Printer) (string, error)`

Returns a valid access token for the provider context. Automatically refreshes if expired.

**Parameters:**
- `p`: Printer for debug output

**Returns:**
- `string`: Valid access token
- `error`: `NotAuthenticatedError` if no credentials found

---

#### `IsProviderAuthenticated() bool`

Checks if provider credentials exist.

**Returns:**
- `bool`: `true` if authenticated, `false` otherwise

### Types

#### `NotAuthenticatedError`

Error type indicating that no provider credentials are available.

```go
type NotAuthenticatedError struct{}

func (e *NotAuthenticatedError) Error() string
```

## CLI Commands Reference

For users of the Terraform Provider/SDK:

```bash
# Authenticate (opens browser)
stackit auth provider login

# Check authentication status
stackit auth provider status

# Get current access token (for debugging)
stackit auth provider get-access-token

# Logout
stackit auth provider logout
```

## See Also

- [STACKIT CLI Documentation](https://github.com/stackitcloud/stackit-cli)
- [STACKIT SDK Go](https://github.com/stackitcloud/stackit-sdk-go)
- [STACKIT Terraform Provider](https://github.com/stackitcloud/terraform-provider-stackit)
