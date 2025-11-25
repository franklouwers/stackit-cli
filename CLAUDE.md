# STACKIT CLI - Claude Context Document

This document provides context for AI assistants (particularly Claude) working on the STACKIT CLI codebase. It captures key architectural decisions, patterns, and implementation details.

## Project Overview

The STACKIT CLI is a command-line interface for managing STACKIT cloud resources. It's built in Go using the Cobra framework for commands and integrates with the STACKIT SDK for API interactions.

**Repository:** `github.com/stackitcloud/stackit-cli`
**Language:** Go
**CLI Framework:** Cobra (`github.com/spf13/cobra`)
**Configuration:** Viper (`github.com/spf13/viper`)
**SDK:** `github.com/stackitcloud/stackit-sdk-go`

## Project Structure

```
stackit-cli/
├── main.go                    # Entry point
├── internal/
│   ├── cmd/                   # All CLI commands (Cobra commands)
│   │   ├── root.go           # Root command and registration
│   │   ├── auth/             # Authentication commands
│   │   ├── config/           # Configuration commands
│   │   ├── project/          # Project management commands
│   │   └── [service]/        # Service-specific commands (dns, ske, etc.)
│   └── pkg/                  # Reusable packages and core business logic
│       ├── auth/             # Authentication logic
│       ├── config/           # Configuration management
│       ├── print/            # Output formatting and printing
│       ├── errors/           # Custom error types
│       └── utils/            # Utility functions
├── go.mod                    # Go module definition
└── go.sum                    # Go module checksums
```

## Authentication Architecture

### Overview

The STACKIT CLI supports three authentication flows:

1. **User Token Flow** - Browser-based OAuth2 PKCE for personal accounts
2. **Service Account Token Flow** - Long-lived token authentication
3. **Service Account Key Flow** - Key-based authentication with automatic token refresh

### Key Components

#### Storage Layer (`internal/pkg/auth/storage.go`)

**Purpose:** Manages credential storage with keyring and file fallback.

**Storage Strategy:**
- **Primary:** System keyring via `github.com/zalando/go-keyring`
  - macOS: Keychain
  - Windows: Credential Manager
  - Linux: Secret Service (libsecret)
- **Fallback:** Base64-encoded JSON file (when keyring unavailable)

**Storage Contexts:**

The storage layer supports two independent storage contexts for credential isolation:

- **CLI Context** (`StorageContextCLI`) - Used by `stackit auth` commands for CLI authentication
- **Provider Context** (`StorageContextProvider`) - Used by `stackit auth provider` commands for Terraform Provider/SDK authentication

**Keyring Service Names:**
| Context | Default Profile | Named Profile |
|---------|----------------|---------------|
| CLI | `stackit-cli` | `stackit-cli/{profile-name}` |
| Provider | `stackit-cli-provider` | `stackit-cli-provider/{profile-name}` |

**File Locations:**
| Context | Default Profile | Named Profile |
|---------|----------------|---------------|
| CLI | `~/.stackit/cli-auth-storage.txt` | `~/.stackit/profiles/{profile-name}/cli-auth-storage.txt` |
| Provider | `~/.stackit/cli-provider-auth-storage.txt` | `~/.stackit/profiles/{profile-name}/cli-provider-auth-storage.txt` |

**File Format:**
```
Base64(JSON({
  "auth_flow_type": "user_token",
  "access_token": "...",
  "refresh_token": "...",
  "user_email": "...",
  "session_expires_at_unix": "...",
  "idp_token_endpoint": "..."
}))
```

**Key Constants:**
```go
const (
    keyringService     = "stackit-cli"
    textFileName       = "cli-auth-storage.txt"
    envAccessTokenName = "STACKIT_ACCESS_TOKEN"
)
```

**Auth Field Keys:**
```go
const (
    SESSION_EXPIRES_AT_UNIX authFieldKey = "session_expires_at_unix"
    ACCESS_TOKEN            authFieldKey = "access_token"
    REFRESH_TOKEN           authFieldKey = "refresh_token"
    SERVICE_ACCOUNT_TOKEN   authFieldKey = "service_account_token"
    SERVICE_ACCOUNT_EMAIL   authFieldKey = "service_account_email"
    USER_EMAIL              authFieldKey = "user_email"
    SERVICE_ACCOUNT_KEY     authFieldKey = "service_account_key"
    PRIVATE_KEY             authFieldKey = "private_key"
    TOKEN_CUSTOM_ENDPOINT   authFieldKey = "token_custom_endpoint"
    IDP_TOKEN_ENDPOINT      authFieldKey = "idp_token_endpoint"
)
```

**Auth Flows:**
```go
const (
    AUTH_FLOW_USER_TOKEN            AuthFlow = "user_token"
    AUTH_FLOW_SERVICE_ACCOUNT_TOKEN AuthFlow = "sa_token"
    AUTH_FLOW_SERVICE_ACCOUNT_KEY   AuthFlow = "sa_key"
)
```

**Key Functions:**
- `SetAuthField(key, value)` - Store credential field (tries keyring, falls back to file)
- `GetAuthField(key)` - Retrieve credential field (tries keyring, falls back to file)
- `DeleteAuthField(key)` - Remove credential field
- `LoginUser(email, accessToken, refreshToken, sessionExpiresAtUnix)` - Store user login
- `LogoutUser()` - Remove user authentication
- `GetAuthFlow()` - Get current authentication flow type
- `SetAuthFlow(flow)` - Set authentication flow type

#### User Login Flow (`internal/pkg/auth/user_login.go`)

**Purpose:** Implements OAuth2 PKCE flow for user authentication.

**Key Function:** `AuthorizeUser(p *print.Printer, isReauthentication bool) error`

**Flow:**
1. Fetch well-known OIDC configuration from IDP
2. Generate PKCE code verifier and challenge
3. Start local HTTP server on localhost:8000-8020 (tries ports sequentially)
4. Open browser to authorization URL
5. User authenticates in browser
6. IDP redirects to localhost with authorization code
7. Exchange code for access and refresh tokens
8. Store tokens in storage via `LoginUser()`
9. Display success page in browser

**OAuth2 Configuration:**
- **IDP:** `https://accounts.stackit.cloud/.well-known/openid-configuration`
- **Client ID:** `stackit-cli-0000-0000-000000000001`
- **Scopes:** `openid offline_access email`
- **Redirect Ports:** 8000-8020 (tries sequentially)

**HTML Templates:**
- Success page: `internal/pkg/auth/templates/login-successful.html`
- Logo: `internal/pkg/auth/templates/stackit_nav_logo_light.svg`

#### Token Management (`internal/pkg/auth/auth.go`)

**Purpose:** Manages token validation, refresh, and authentication configuration.

**Key Functions:**

1. **`AuthenticationConfig(p *print.Printer, reauthorizeUserRoutine func(...) error) (sdkConfig.ConfigurationOption, error)`**
   - Reads credentials from storage
   - Initializes appropriate auth flow (user token, SA token, SA key)
   - Returns SDK configuration option
   - Handles session expiration and re-authentication

2. **`UserSessionExpired() (bool, error)`**
   - Checks if session has expired based on `SESSION_EXPIRES_AT_UNIX`
   - Default session timeout: 2 hours (configurable via `session_time_limit`)

3. **`GetAccessToken() (string, error)`**
   - Retrieves access token from storage
   - Does not refresh

4. **`GetValidAccessToken(p *print.Printer) (string, error)`**
   - Retrieves access token
   - Automatically refreshes if expired (user token flow only)
   - Returns valid token

**Token Refresh Logic:**
- Access tokens are JWT tokens with expiration
- Token expiration checked via `TokenExpired(token)` function
- If expired, uses refresh token to get new access token
- New tokens stored back to storage
- If refresh fails, user must re-authenticate

#### Token Refresh Flow (`internal/pkg/auth/user_token_flow.go`)

**Purpose:** Implements `http.RoundTripper` for automatic token injection and refresh.

**Key Type:**
```go
type userTokenFlow struct {
    printer       *print.Printer
    client        *http.Client
    authFlow      AuthFlow
    accessToken   string
    refreshToken  string
    tokenEndpoint string
}
```

**`RoundTrip(req *http.Request) (*http.Response, error)` Flow:**
1. Load tokens from storage (if not already loaded)
2. Check if access token is expired
3. If expired, refresh tokens via `refreshTokens()`
4. If refresh fails, re-authenticate user
5. Add `Authorization: Bearer <token>` header to request
6. Execute request

**Token Refresh Process:**
1. Build POST request to IDP token endpoint
2. Include `grant_type=refresh_token` and refresh token
3. Parse response for new access and refresh tokens
4. Store new tokens in storage
5. Update in-memory tokens

#### Service Account Authentication (`internal/pkg/auth/service_account.go`)

**Purpose:** Handles service account authentication (token and key flows).

**Key Function:** `AuthenticateServiceAccount(...) (string, string, error)`
- Accepts either SA token or SA key + private key
- Extracts access token and email
- Stores credentials in storage
- Returns email and access token

**Key Flow Integration:**
- `initKeyFlowWithStorage()` - Loads SA key from storage and initializes SDK key flow
- `keyFlowWithStorage` - Wraps SDK's key flow to persist tokens after each request

### Auth Commands (`internal/cmd/auth/`)

**Command Structure:**
```
stackit auth
├── login                        # User login (OAuth2 PKCE)
├── logout                       # User logout
├── activate-service-account     # SA authentication
└── get-access-token            # Get current access token
```

**`login` Command:** (`internal/cmd/auth/login/login.go`)
- Calls `auth.AuthorizeUser(p, false)`
- Opens browser for OAuth2 flow
- Stores credentials

**`logout` Command:** (`internal/cmd/auth/logout/logout.go`)
- Calls `auth.LogoutUser()`
- Removes access token, refresh token, user email, session expiration

**`activate-service-account` Command:** (`internal/cmd/auth/activate-service-account/activate_service_account.go`)
- Flags:
  - `--service-account-token` - Long-lived SA token
  - `--service-account-key-path` - Path to SA key JSON
  - `--private-key-path` - Optional RSA private key
  - `--only-print-access-token` - Print token without storing
- Calls `auth.AuthenticateServiceAccount()`

**`get-access-token` Command:** (`internal/cmd/auth/get-access-token/get_access_token.go`)
- Calls `auth.GetValidAccessToken(p)`
- Automatically refreshes if expired
- Supports JSON output format

### Provider Auth Commands (`internal/cmd/auth/provider/`)

**Purpose:** Enables Terraform Provider and SDK to use CLI user credentials instead of requiring service accounts for local development.

**Command Structure:**
```
stackit auth provider
├── login                        # Provider login (OAuth2 PKCE)
├── logout                       # Provider logout
├── get-access-token            # Get provider access token
└── status                      # Show provider auth status
```

**Key Features:**
- **Independent Storage:** Provider auth uses separate storage (`StorageContextProvider`) from CLI auth
- **Concurrent Auth:** CLI and Provider can be authenticated simultaneously with different accounts
- **Automatic Token Refresh:** `get-access-token` automatically refreshes expired tokens
- **Profile Support:** Each profile has independent CLI and Provider authentication

**`provider login` Command:** (`internal/cmd/auth/provider/login/login.go`)
- Calls `auth.AuthorizeUser(p, auth.StorageContextProvider, false)`
- Opens browser for OAuth2 flow
- Stores credentials in Provider context

**`provider logout` Command:** (`internal/cmd/auth/provider/logout/logout.go`)
- Calls `auth.LogoutUserWithContext(auth.StorageContextProvider)`
- Only removes Provider credentials, CLI auth unaffected

**`provider get-access-token` Command:** (`internal/cmd/auth/provider/get-access-token/get_access_token.go`)
- Calls `auth.GetValidAccessTokenWithContext(p, auth.StorageContextProvider)`
- Automatically refreshes if expired
- Writes refreshed tokens back to storage for bidirectional sync

**`provider status` Command:** (`internal/cmd/auth/provider/status/status.go`)
- Shows Provider authentication status (authenticated/not authenticated)
- Displays user email and auth flow type
- Supports JSON output format

**Usage Example:**
```bash
# Login for Provider/SDK
$ stackit auth provider login
# Opens browser, stores credentials separately from CLI

# Get access token (with auto-refresh)
$ stackit auth provider get-access-token
eyJhbGc...

# Check status
$ stackit auth provider status
Provider Authentication Status: Authenticated
Email: user@example.com
Auth Flow: user_token

# Logout from Provider only (CLI auth unaffected)
$ stackit auth provider logout
```

## Configuration Management

### Config Files (`internal/pkg/config/config.go`)

**Config File Locations:**
- Default profile: `~/.config/stackit/cli-config.json`
- Named profile: `~/.config/stackit/profiles/{profile-name}/cli-config.json`

**Key Configuration Keys:**
```go
const (
    SessionTimeLimitKey = "session_time_limit"  // Default: "2h"
    ProjectIdKey        = "project_id"
    RegionKey           = "region"              // Default: "eu01"
    OutputFormatKey     = "output_format"
    VerbosityKey        = "verbosity"
    // ... service-specific endpoint keys
    IdentityProviderCustomWellKnownConfigurationKey
    IdentityProviderCustomClientIdKey
    // ... many more
)
```

**Environment Variables:**
- Prefix: `STACKIT_`
- Example: `STACKIT_SESSION_TIME_LIMIT`, `STACKIT_PROJECT_ID`
- Special: `STACKIT_ACCESS_TOKEN` bypasses stored credentials

### Profiles (`internal/pkg/config/profiles.go`)

**Active Profile Storage:** `~/.config/stackit/cli-profile.txt`
**Environment Override:** `STACKIT_CLI_PROFILE`
**Default Profile Name:** `"default"`

**Profile Structure:**
Each profile has:
- Independent config file (`cli-config.json`)
- Independent auth storage (keyring entries or `cli-auth-storage.txt`)
- Independent keyring namespace (`stackit-cli/{profile-name}`)

**Key Functions:**
- `GetProfile()` - Returns active profile name
- `SetProfile(name)` - Sets active profile
- `CreateProfile(name)` - Creates new profile
- `DeleteProfile(name)` - Deletes profile (cannot delete default)

## Command Structure Patterns

### Standard Command Pattern

Most commands follow this structure:

```go
package commandname

import (
    "github.com/spf13/cobra"
    "github.com/stackitcloud/stackit-cli/internal/cmd/params"
    "github.com/stackitcloud/stackit-cli/internal/pkg/args"
    "github.com/stackitcloud/stackit-cli/internal/pkg/examples"
)

func NewCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "command-name",
        Short: "Short description",
        Long:  "Long description",
        Args:  args.NoArgs,  // or args.SingleArg, etc.
        Example: examples.Build(
            examples.NewExample(
                `Description of example`,
                "$ stackit command-name"),
        ),
        RunE: func(cmd *cobra.Command, args []string) error {
            // 1. Parse input
            model, err := parseInput(params.Printer, cmd, args)
            if err != nil {
                return err
            }

            // 2. Execute business logic
            // ...

            // 3. Output result
            params.Printer.Outputln("Success message")

            return nil
        },
    }

    // Add flags
    cmd.Flags().StringVar(&flagVar, "flag-name", "", "description")

    return cmd
}

func parseInput(p *print.Printer, cmd *cobra.Command, args []string) (*inputModel, error) {
    globalFlags := globalflags.Parse(p, cmd)

    model := inputModel{
        GlobalFlagModel: globalFlags,
        // ... parse other flags
    }

    p.DebugInputModel(model)
    return &model, nil
}
```

### Command Group Pattern

Command groups (like `auth`, `config`, `project`) use this pattern:

```go
package commandgroup

import (
    "github.com/spf13/cobra"
    "github.com/stackitcloud/stackit-cli/internal/cmd/params"
    "github.com/stackitcloud/stackit-cli/internal/pkg/args"
    "github.com/stackitcloud/stackit-cli/internal/pkg/utils"
)

func NewCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "group-name",
        Short: "Short description",
        Long:  "Long description",
        Args:  args.NoArgs,
        Run:   utils.CmdHelp,  // Shows help by default
    }
    addSubcommands(cmd, params)
    return cmd
}

func addSubcommands(cmd *cobra.Command, params *params.CmdParams) {
    cmd.AddCommand(subcommand1.NewCmd(params))
    cmd.AddCommand(subcommand2.NewCmd(params))
    // ...
}
```

## Testing Patterns

### Unit Test Structure

Tests are typically in `*_test.go` files in the same package.

**Common Test Patterns:**

```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name           string
        input          inputType
        expectedOutput outputType
        expectedError  error
    }{
        {
            name:  "success case",
            input: ...,
            expectedOutput: ...,
            expectedError: nil,
        },
        {
            name:  "error case",
            input: ...,
            expectedOutput: ...,
            expectedError: errors.New("expected error"),
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            output, err := FunctionName(tt.input)

            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.expectedError.Error())
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedOutput, output)
            }
        })
    }
}
```

## Code Style and Conventions

### Naming Conventions

- **Commands:** kebab-case (e.g., `get-access-token`, `activate-service-account`)
- **Go files:** snake_case (e.g., `user_login.go`, `get_access_token.go`)
- **Go packages:** lowercase single word (e.g., `auth`, `config`, `utils`)
- **Constants:** SCREAMING_SNAKE_CASE or PascalCase depending on visibility
- **Functions:** PascalCase for exported, camelCase for internal

### Error Handling

**Standard Pattern:**
```go
result, err := SomeFunction()
if err != nil {
    return fmt.Errorf("context about what failed: %w", err)
}
```

**Custom Errors:**
Defined in `internal/pkg/errors/`:
```go
type SessionExpiredError struct{}
type DeleteDefaultProfile struct{ DefaultProfile string }
```

### Logging/Debugging

Uses `print.Printer` for output:
```go
p.Debug(print.DebugLevel, "debug message: %v", value)
p.Debug(print.ErrorLevel, "error message: %v", err)
p.Warn("warning message: %s", msg)
p.Outputln("user-visible message")
p.Outputf("formatted message: %s", value)
```

## Dependencies

### Key External Libraries

- **`github.com/spf13/cobra`** - CLI framework
- **`github.com/spf13/viper`** - Configuration management
- **`github.com/zalando/go-keyring`** - OS keyring access
- **`golang.org/x/oauth2`** - OAuth2 client
- **`github.com/golang-jwt/jwt/v5`** - JWT token parsing
- **`github.com/stackitcloud/stackit-sdk-go`** - STACKIT API client

### SDK Integration

The CLI uses the STACKIT SDK for all API calls:

```go
import (
    sdkConfig "github.com/stackitcloud/stackit-sdk-go/core/config"
    "github.com/stackitcloud/stackit-sdk-go/services/dns"
)

// Get auth config
authCfgOption, err := auth.AuthenticationConfig(p, auth.AuthorizeUser)
if err != nil {
    return err
}

// Create service client
client, err := dns.NewAPIClient(authCfgOption)
if err != nil {
    return err
}

// Make API calls
resp, err := client.CreateZone(ctx, projectId).CreateZonePayload(payload).Execute()
```

## Common Pitfalls and Gotchas

### 1. Storage Keyring vs File

Always handle both keyring and file storage:
- Keyring may not be available (headless systems, unsupported OS)
- File is created automatically as fallback
- Functions like `SetAuthField` handle fallback automatically

### 2. Profile Awareness

Most auth and config functions are profile-aware:
- Always get active profile first: `config.GetProfile()`
- Storage locations differ per profile
- Keyring service names differ per profile

### 3. Token Expiration

- Access tokens expire (typically 1 hour)
- Session expires separately (default 2 hours)
- Always use `GetValidAccessToken` for auto-refresh
- Check session expiration before operations

### 4. Environment Variable Override

`STACKIT_ACCESS_TOKEN` completely bypasses stored credentials:
- Check for this env var first in auth logic
- Users may set it for CI/CD or temporary override
- Does not affect stored credentials

### 5. Error Wrapping

Always wrap errors with context:
```go
// Good
return fmt.Errorf("get auth field %s: %w", key, err)

// Bad
return err
```

## Ongoing Work: Provider Auth Feature

See `PLAN.md` for detailed implementation plan.

**Summary:**
- Adding new command group: `stackit auth provider`
- Separate storage for provider auth (keyring: `stackit-cli-provider`, file: `cli-provider-auth-storage.txt`)
- Allows Terraform Provider and SDK to use CLI user credentials
- Refactoring storage layer to support multiple storage contexts
- Maintaining backward compatibility with existing commands

**Key Changes:**
1. Storage layer refactored to support storage contexts (CLI vs Provider)
2. User login flow refactored to support different storage contexts
3. New commands: `provider login`, `provider logout`, `provider get-access-token`, `provider status`
4. Token management extended for provider context

## Useful Commands for Development

```bash
# Build the CLI
go build -o stackit

# Run tests
go test ./...

# Run specific test
go test -v ./internal/pkg/auth -run TestAuthorizeUser

# Run with debug output
./stackit --verbosity debug auth login

# Check current profile
cat ~/.config/stackit/cli-profile.txt

# View config
cat ~/.config/stackit/cli-config.json

# View auth storage (base64 encoded)
cat ~/.stackit/cli-auth-storage.txt | base64 -d

# Check keyring entries (macOS)
security find-generic-password -s "stackit-cli" -a "access_token"
```

## Architecture Diagrams

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│ CLI Command Execution                                        │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ auth.AuthenticationConfig()                                  │
│  - Checks STACKIT_ACCESS_TOKEN env var                      │
│  - Gets auth flow from storage                              │
│  - Checks session expiration                                │
└────────────────┬────────────────────────────────────────────┘
                 │
      ┌──────────┴──────────┬──────────────┐
      ▼                     ▼              ▼
┌──────────┐         ┌──────────┐    ┌──────────┐
│User Token│         │ SA Token │    │  SA Key  │
└────┬─────┘         └────┬─────┘    └────┬─────┘
     │                    │               │
     ▼                    ▼               ▼
┌──────────────┐    ┌──────────────┐ ┌──────────────┐
│Check Expired │    │Check Expired │ │Check Expired │
│   Refresh    │    │Return Token  │ │Refresh via   │
│  /Reauth     │    │              │ │   SDK        │
└──────┬───────┘    └──────┬───────┘ └──────┬───────┘
       │                   │                │
       └───────────────────┴────────────────┘
                           │
                           ▼
                  ┌────────────────┐
                  │Configure SDK   │
                  │    Client      │
                  └────────┬───────┘
                           │
                           ▼
                  ┌────────────────┐
                  │Execute API Call│
                  └────────────────┘
```

### Storage Strategy

```
┌──────────────────────────────────────────────────────────────┐
│ Set/Get Auth Field                                            │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
         ┌───────────────┐
         │Get Active     │
         │Profile        │
         └───────┬───────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌──────────────┐   ┌─────────────────┐
│Default       │   │Named Profile    │
│Profile       │   │(e.g., "dev")    │
└──────┬───────┘   └────────┬────────┘
       │                    │
       ▼                    ▼
┌──────────────────────────────────────┐
│Try Keyring                            │
│  Service: stackit-cli[/{profile}]    │
│  Account: {auth_field_key}           │
└────────┬─────────────────────────────┘
         │
         ▼
    ┌────────┐
    │Success?│
    └───┬─┬──┘
        │ │
     NO │ │ YES
        │ └─────────────────┐
        ▼                   │
┌──────────────────┐        │
│Try File Fallback │        │
│  ~/.stackit/...  │        │
└────────┬─────────┘        │
         │                  │
         ▼                  │
    ┌────────┐              │
    │Success?│              │
    └───┬─┬──┘              │
        │ │                 │
     NO │ │ YES             │
        │ │                 │
        │ └────┐            │
        ▼      │            │
    ┌────────┐ │            │
    │ Error  │ │            │
    └────────┘ │            │
               │            │
               └────────────┘
                     │
                     ▼
               ┌──────────┐
               │  Return  │
               │  Value   │
               └──────────┘
```

## Token Refresh Best Practices

### Critical Requirements for OAuth2 Token Refresh

Based on research and the CLI's existing implementation, token refresh mechanisms must meet these requirements:

#### 1. Per-Request Expiration Checks

**Pattern:** Check token expiration on **every HTTP request**, not just at initialization.

```go
func (utf *userTokenFlow) RoundTrip(req *http.Request) (*http.Response, error) {
    // ALWAYS check expiration before each request
    if TokenExpired(utf.accessToken) {
        err := refreshTokens(utf)
        if err != nil {
            return nil, err
        }
    }
    // ... execute request
}
```

**Why:** Long-running operations (e.g., Terraform apply with many resources) can exceed token lifetimes. Tokens checked only at startup will fail mid-operation.

#### 2. Proactive Refresh Window

**Pattern:** Refresh tokens **before** they expire, not after.

```go
func tokenExpiresSoon(token string, buffer time.Duration) bool {
    exp := parseTokenExpiration(token)
    // Check if token expires within buffer window
    return time.Now().Add(buffer).After(exp)
}

// Usage: Check if token expires within 5 seconds
if tokenExpiresSoon(accessToken, 5*time.Second) {
    refreshTokens()
}
```

**Why:** Prevents timing issues with upstream systems. STACKIT SDK refreshes 5 seconds before expiration for this reason.

#### 3. Token Rotation - Both Tokens Update

**Critical:** OAuth2 refresh responses include **both** a new access token AND a new refresh token.

```go
type RefreshResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`  // Not just access token!
}

// MUST update both in storage
SetAuthFieldMap(map[authFieldKey]string{
    ACCESS_TOKEN:  newAccessToken,
    REFRESH_TOKEN: newRefreshToken,  // Both tokens rotate
})
```

**Why:** Refresh tokens are single-use or have limited reuse. Using the old refresh token after rotation may fail.

#### 4. Write-Back to Storage (Bidirectional Sync)

**Critical:** When tokens are refreshed in memory, they **MUST** be written back to storage.

```go
func refreshTokens(utf *userTokenFlow) error {
    // 1. Call IDP to refresh
    newAccess, newRefresh := callTokenEndpoint(utf.refreshToken)

    // 2. Write BACK to storage (keyring/file)
    SetAuthField(ACCESS_TOKEN, newAccess)
    SetAuthField(REFRESH_TOKEN, newRefresh)

    // 3. Update in-memory values
    utf.accessToken = newAccess
    utf.refreshToken = newRefresh
}
```

**Why:**
- Multiple processes may use the same credentials (CLI + Terraform)
- Concurrent operations must see consistent token state
- Prevents multiple simultaneous refresh attempts
- Enables bidirectional sync: CLI can use tokens refreshed by Terraform and vice versa

#### 5. Thread Safety with Mutex

**Pattern:** Protect token refresh operations with `sync.Mutex`.

```go
type userTokenFlow struct {
    mu            sync.Mutex  // Protects token fields
    accessToken   string
    refreshToken  string
}

func (utf *userTokenFlow) RoundTrip(req *http.Request) (*http.Response, error) {
    utf.mu.Lock()
    defer utf.mu.Unlock()

    // Safe to check and refresh tokens
    if TokenExpired(utf.accessToken) {
        refreshTokens(utf)
    }
    // ... execute request
}
```

**Why:** `http.RoundTripper` may be called concurrently. Without mutex:
- Race conditions on token variables
- Multiple simultaneous refresh requests
- Corrupted token state

#### 6. Token Expiration Parsing

**Pattern:** Use JWT parsing to check expiration without verifying signature.

```go
func TokenExpired(token string) (bool, error) {
    // ParseUnverified is safe for expiration checks
    // We're not authenticating, just reading the expiration claim
    parsedToken, _, err := jwt.NewParser().ParseUnverified(token, &jwt.RegisteredClaims{})
    if err != nil {
        return false, fmt.Errorf("parse access token: %w", err)
    }

    exp, err := parsedToken.Claims.GetExpirationTime()
    if err != nil || exp == nil {
        return false, nil
    }

    return time.Now().After(exp.Time), nil
}
```

**Why:** Access tokens are JWTs. No need to verify signature just to check expiration time.

### Implementation Reference

The CLI's `internal/pkg/auth/user_token_flow.go` demonstrates all these patterns correctly:

1. ✅ Per-request expiration check in `RoundTrip()`
2. ✅ Token rotation in `refreshTokens()` - both tokens update
3. ✅ Write-back to storage via `SetAuthFieldMap()`
4. ✅ JWT parsing in `TokenExpired()`
5. ⚠️  Missing: Explicit mutex (single-threaded CLI context)
6. ⚠️  Missing: Proactive refresh window (checks if already expired)

When implementing provider auth for Terraform/SDK, **add** the missing mutex and proactive refresh window.

## Recent Updates

**Last Updated:** 2025-11-25

**Major Changes:**
- ✅ **Provider Auth Feature Implemented** - Complete implementation of `stackit auth provider` commands
- ✅ **Storage Layer Refactored** - Added `StorageContext` support for CLI and Provider credential isolation
- ✅ **Token Management Enhanced** - Context-aware token refresh with bidirectional sync
- ✅ **Comprehensive Testing** - Added 14 integration tests (10 from Phase 1 + 4 from Phase 5)
- ✅ **Commands Added:** `provider login`, `provider logout`, `provider get-access-token`, `provider status`

**Implementation Details:**
- Storage contexts (`StorageContextCLI` and `StorageContextProvider`) enable independent authentication
- All storage operations have `*WithContext()` variants for explicit context control
- User login flow (`AuthorizeUser`) accepts context parameter for flexible authentication
- Token refresh automatically writes updated tokens back to correct storage context
- Each profile supports independent CLI and Provider authentication

---

*This document is maintained as part of the STACKIT CLI project to provide context for AI assistants and new developers. When making significant architectural changes, please update this document.*
