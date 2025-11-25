# Implementation Plan: CLI Authentication for Terraform Provider & SDK

## Executive Summary

This document outlines the implementation plan for adding CLI-based authentication support to the STACKIT Terraform Provider and SDK. This feature will allow users to authenticate with their personal STACKIT account via the CLI and use those credentials in the Terraform Provider and SDK, eliminating the need to create service accounts for local development.

## Current State

### Existing Authentication Architecture

The STACKIT CLI currently supports three authentication flows:

1. **User Token Flow** (`AUTH_FLOW_USER_TOKEN`)
   - Browser-based OAuth2 PKCE authentication
   - Stores: `access_token`, `refresh_token`, `user_email`, `session_expires_at_unix`
   - Used by: `stackit auth login`

2. **Service Account Token Flow** (`AUTH_FLOW_SERVICE_ACCOUNT_TOKEN`)
   - Long-lived token authentication
   - Stores: `service_account_token`, `service_account_email`
   - Used by: `stackit auth activate-service-account --service-account-token`

3. **Service Account Key Flow** (`AUTH_FLOW_SERVICE_ACCOUNT_KEY`)
   - Key-based authentication with token refresh
   - Stores: `service_account_key`, `private_key`, `service_account_email`
   - Used by: `stackit auth activate-service-account --service-account-key-path`

### Current Storage Strategy

**Primary Storage:** System keychain via `github.com/zalando/go-keyring`
- Service name: `stackit-cli` (or `stackit-cli/{profile-name}` for non-default profiles)
- Keyring account: `{auth_field_key}` (e.g., `access_token`, `refresh_token`)

**Fallback Storage:** Base64-encoded JSON file
- Location: `~/.stackit/cli-auth-storage.txt` (or `~/.stackit/profiles/{profile-name}/cli-auth-storage.txt`)
- Format: Base64-encoded JSON with auth field key-value pairs
- Permissions: `0o600` (read/write for owner only)

### Key Implementation Files

- `internal/pkg/auth/storage.go` - Credential storage with keyring/file fallback
- `internal/pkg/auth/user_login.go` - OAuth2 PKCE flow implementation (`AuthorizeUser` function)
- `internal/pkg/auth/auth.go` - Authentication configuration and token management
- `internal/pkg/auth/user_token_flow.go` - Token refresh logic for user authentication
- `internal/cmd/auth/` - Auth command implementations (`login`, `logout`, `activate-service-account`, `get-access-token`)

## Goals and Requirements

### Primary Goals

1. Enable Terraform Provider and SDK to authenticate using CLI user credentials
2. Maintain separation between CLI's own auth and external app auth
3. Provide explicit opt-in mechanism (no surprises for users)
4. Ensure credentials are stored securely (keychain or file)
5. Support automatic token refresh
6. Avoid strong dependency between CLI and SDK

### Non-Goals

1. Sharing configuration beyond tokens (users must configure endpoints separately)
2. Automatic synchronization of auth state between CLI and external apps
3. Supporting multiple simultaneous provider auth sessions (one provider auth per profile)

### Requirements

- Strong separation: CLI auth and provider auth use different storage
- Explicit enable: Users must explicitly run provider login command
- No confusion: Clear naming and messaging about provider vs CLI auth
- Easy integration: Simple for Terraform Provider/SDK to consume
- Token refresh: Provider auth should refresh tokens automatically
- Profile support: Each CLI profile can have independent provider auth

## Proposed Architecture

### Storage Strategy (Combined Option 1 + 2)

**Primary:** System keychain with dedicated service name
- Service name: `stackit-cli-provider` (or `stackit-cli-provider/{profile-name}`)
- Same auth fields as user token flow
- Independent from CLI's own auth

**Fallback:** Dedicated JSON file
- Location: `~/.stackit/cli-provider-auth-storage.txt` (or `~/.stackit/profiles/{profile-name}/cli-provider-auth-storage.txt`)
- Format: Base64-encoded JSON (same as existing fallback)
- Permissions: `0o600`

### Command Structure

New command group: `stackit auth provider` (separate from existing `stackit auth`)

Commands:
```bash
# Login for provider/SDK use (opens browser, stores credentials in provider-specific storage)
stackit auth provider login

# Logout from provider/SDK auth (clears provider-specific credentials)
stackit auth provider logout

# Get current provider access token (with automatic refresh)
stackit auth provider get-access-token

# Check provider auth status
stackit auth provider status
```

### Interface Between CLI and SDK/Terraform Provider

**Option Selected:** Keychain + File (Combined Option 1 + 2)

The SDK and Terraform Provider will:
1. Check for keychain entries under service `stackit-cli-provider`
2. Fall back to reading `~/.stackit/cli-provider-auth-storage.txt`
3. Extract `access_token`, `refresh_token`, and `idp_token_endpoint`
4. Handle token refresh independently using the refresh token
5. Write refreshed tokens back to storage

**Data Shared:**
- `access_token` - Current access token
- `refresh_token` - Refresh token for getting new access tokens
- `idp_token_endpoint` - IDP token endpoint URL for refresh
- `user_email` - Email of authenticated user (for display/logging)
- `session_expires_at_unix` - Session expiration timestamp

## Implementation Plan

### Phase 1: Refactor Storage Layer

**Goal:** Make storage functions flexible to support multiple storage contexts (CLI vs Provider)

**Changes to `internal/pkg/auth/storage.go`:**

1. Add new storage context constants:
```go
type StorageContext string

const (
    StorageContextCLI      StorageContext = "cli"      // For CLI's own auth
    StorageContextProvider StorageContext = "provider" // For provider/SDK auth
)
```

2. Add context-aware storage functions:
```go
// Get keyring service name based on context and profile
func getKeyringService(context StorageContext, profile string) string

// Get text file name based on context
func getTextFileName(context StorageContext) string

// Context-aware auth field operations
func SetAuthFieldWithContext(context StorageContext, key authFieldKey, value string) error
func GetAuthFieldWithContext(context StorageContext, key authFieldKey) (string, error)
func DeleteAuthFieldWithContext(context StorageContext, key authFieldKey) error

// Context-aware bulk operations
func SetAuthFieldMapWithContext(context StorageContext, keyMap map[authFieldKey]string) error
func GetAuthFieldMapWithContext(context StorageContext, keyMap map[authFieldKey]string) error

// Context-aware login/logout
func LoginUserWithContext(context StorageContext, email, accessToken, refreshToken, sessionExpiresAtUnix string) error
func LogoutUserWithContext(context StorageContext) error
func GetAuthFlowWithContext(context StorageContext) (AuthFlow, error)
func SetAuthFlowWithContext(context StorageContext, value AuthFlow) error
```

3. Update existing functions to use `StorageContextCLI` by default:
```go
// Existing functions now delegate to context-aware versions
func SetAuthField(key authFieldKey, value string) error {
    return SetAuthFieldWithContext(StorageContextCLI, key, value)
}

func GetAuthField(key authFieldKey) (string, error) {
    return GetAuthFieldWithContext(StorageContextCLI, key)
}
// ... etc for all existing functions
```

**Files Modified:**
- `internal/pkg/auth/storage.go` - Add context-aware storage functions

**Backward Compatibility:**
- All existing code continues to work unchanged
- Existing functions delegate to context-aware versions with `StorageContextCLI`

### Phase 2: Refactor User Login Flow

**Goal:** Make `AuthorizeUser` flexible to support both CLI and provider login

**Changes to `internal/pkg/auth/user_login.go`:**

1. Add new function signature:
```go
// AuthorizeUserWithContext implements the PKCE OAuth2 flow for a specific storage context
func AuthorizeUserWithContext(p *print.Printer, isReauthentication bool, context StorageContext) error
```

2. Update the function to use context-aware storage:
```go
func AuthorizeUserWithContext(p *print.Printer, isReauthentication bool, context StorageContext) error {
    // ... existing PKCE flow logic ...

    // Instead of SetAuthFlow(AUTH_FLOW_USER_TOKEN)
    err = SetAuthFlowWithContext(context, AUTH_FLOW_USER_TOKEN)

    // Instead of LoginUser(email, accessToken, refreshToken, sessionExpiresAtUnix)
    err = LoginUserWithContext(context, email, accessToken, refreshToken, sessionExpiresAtUnix)

    // Instead of GetAuthField(USER_EMAIL)
    email, err := GetAuthFieldWithContext(context, USER_EMAIL)

    // ... rest of the logic ...
}
```

3. Update existing `AuthorizeUser` to delegate:
```go
func AuthorizeUser(p *print.Printer, isReauthentication bool) error {
    return AuthorizeUserWithContext(p, isReauthentication, StorageContextCLI)
}
```

**Files Modified:**
- `internal/pkg/auth/user_login.go` - Add context parameter to login flow

**Backward Compatibility:**
- Existing `AuthorizeUser` calls continue to work unchanged
- New provider login will use `AuthorizeUserWithContext(..., StorageContextProvider)`

### Phase 3: Create Provider Auth Commands

**Goal:** Implement new command group `stackit auth provider`

**New Files to Create:**

1. `internal/cmd/auth/provider/provider.go` - Provider auth command group
```go
package provider

func NewCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "provider",
        Short: "Authenticate for Terraform Provider and SDK usage",
        Long:  "Authenticate using your personal account for use with the STACKIT Terraform Provider and SDK.",
        Args:  args.NoArgs,
        Run:   utils.CmdHelp,
    }
    addSubcommands(cmd, params)
    return cmd
}

func addSubcommands(cmd *cobra.Command, params *params.CmdParams) {
    cmd.AddCommand(newLoginCmd(params))
    cmd.AddCommand(newLogoutCmd(params))
    cmd.AddCommand(newGetAccessTokenCmd(params))
    cmd.AddCommand(newStatusCmd(params))
}
```

2. `internal/cmd/auth/provider/login.go` - Provider login command
```go
package provider

func newLoginCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "login",
        Short: "Logs in for provider/SDK usage",
        Long: fmt.Sprintf("%s\n%s\n%s",
            "Logs in to enable authentication in the STACKIT Terraform Provider and SDK.",
            "This stores credentials separately from the CLI's own authentication.",
            "The authentication is done via a web-based authorization flow."),
        Args: args.NoArgs,
        Example: examples.Build(
            examples.NewExample(
                `Login for Terraform Provider and SDK usage`,
                "$ stackit auth provider login"),
        ),
        RunE: func(_ *cobra.Command, _ []string) error {
            err := auth.AuthorizeUserWithContext(params.Printer, false, auth.StorageContextProvider)
            if err != nil {
                return fmt.Errorf("authorization failed: %w", err)
            }

            params.Printer.Outputln("Successfully logged in for Terraform Provider and SDK usage.\n")
            params.Printer.Outputln("You can now use 'cli_auth = true' in your Terraform configuration.\n")

            return nil
        },
    }
    return cmd
}
```

3. `internal/cmd/auth/provider/logout.go` - Provider logout command
```go
package provider

func newLogoutCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "logout",
        Short: "Logs out from provider/SDK authentication",
        Long:  "Removes provider/SDK authentication credentials from storage.",
        Args:  args.NoArgs,
        Example: examples.Build(
            examples.NewExample(
                `Logout from provider/SDK authentication`,
                "$ stackit auth provider logout"),
        ),
        RunE: func(_ *cobra.Command, _ []string) error {
            err := auth.LogoutUserWithContext(auth.StorageContextProvider)
            if err != nil {
                return fmt.Errorf("logout failed: %w", err)
            }

            params.Printer.Outputln("Successfully logged out from provider/SDK authentication.\n")

            return nil
        },
    }
    return cmd
}
```

4. `internal/cmd/auth/provider/get_access_token.go` - Get provider access token
```go
package provider

func newGetAccessTokenCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "get-access-token",
        Short: "Prints provider/SDK access token",
        Long:  "Prints a short-lived access token for the provider/SDK authentication.",
        Args:  args.NoArgs,
        Example: examples.Build(
            examples.NewExample(
                `Get provider/SDK access token`,
                "$ stackit auth provider get-access-token"),
        ),
        RunE: func(cmd *cobra.Command, args []string) error {
            model, err := parseInput(params.Printer, cmd, args)
            if err != nil {
                return err
            }

            userSessionExpired, err := auth.UserSessionExpiredWithContext(auth.StorageContextProvider)
            if err != nil {
                return err
            }
            if userSessionExpired {
                return &cliErr.SessionExpiredError{}
            }

            accessToken, err := auth.GetValidAccessTokenWithContext(params.Printer, auth.StorageContextProvider)
            if err != nil {
                params.Printer.Debug(print.ErrorLevel, "get valid access token: %v", err)
                return &cliErr.SessionExpiredError{}
            }

            switch model.OutputFormat {
            case print.JSONOutputFormat:
                details, err := json.MarshalIndent(map[string]string{
                    "access_token": accessToken,
                }, "", "  ")
                if err != nil {
                    return fmt.Errorf("marshal access token: %w", err)
                }
                params.Printer.Outputln(string(details))
                return nil
            default:
                params.Printer.Outputln(accessToken)
                return nil
            }
        },
    }
    return cmd
}
```

5. `internal/cmd/auth/provider/status.go` - Check provider auth status
```go
package provider

func newStatusCmd(params *params.CmdParams) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "status",
        Short: "Shows provider/SDK authentication status",
        Long:  "Displays the current authentication status for Terraform Provider and SDK usage.",
        Args:  args.NoArgs,
        Example: examples.Build(
            examples.NewExample(
                `Check provider/SDK authentication status`,
                "$ stackit auth provider status"),
        ),
        RunE: func(cmd *cobra.Command, args []string) error {
            model, err := parseInput(params.Printer, cmd, args)
            if err != nil {
                return err
            }

            flow, err := auth.GetAuthFlowWithContext(auth.StorageContextProvider)
            if err != nil || flow == "" {
                params.Printer.Outputln("Not authenticated for provider/SDK usage.\n")
                params.Printer.Outputln("Run 'stackit auth provider login' to authenticate.\n")
                return nil
            }

            email, err := auth.GetAuthFieldWithContext(auth.StorageContextProvider, auth.USER_EMAIL)
            if err != nil {
                email = "unknown"
            }

            sessionExpired, err := auth.UserSessionExpiredWithContext(auth.StorageContextProvider)
            if err != nil {
                sessionExpired = true
            }

            status := "active"
            if sessionExpired {
                status = "expired"
            }

            switch model.OutputFormat {
            case print.JSONOutputFormat:
                details, err := json.MarshalIndent(map[string]string{
                    "authenticated": "true",
                    "email":        email,
                    "status":       status,
                }, "", "  ")
                if err != nil {
                    return fmt.Errorf("marshal status: %w", err)
                }
                params.Printer.Outputln(string(details))
                return nil
            default:
                params.Printer.Outputln(fmt.Sprintf("Authenticated as: %s\n", email))
                params.Printer.Outputln(fmt.Sprintf("Status: %s\n", status))
                if sessionExpired {
                    params.Printer.Outputln("Run 'stackit auth provider login' to refresh your session.\n")
                }
                return nil
            }
        },
    }
    return cmd
}
```

**Files Modified:**
- `internal/cmd/auth/auth.go` - Add provider subcommand to auth command group

**Files Created:**
- `internal/cmd/auth/provider/provider.go`
- `internal/cmd/auth/provider/login.go`
- `internal/cmd/auth/provider/logout.go`
- `internal/cmd/auth/provider/get_access_token.go`
- `internal/cmd/auth/provider/status.go`

### Phase 4: Add Context-Aware Token Management

**Goal:** Support token validation and refresh for provider context

**Changes to `internal/pkg/auth/auth.go`:**

1. Add context-aware helper functions:
```go
func UserSessionExpiredWithContext(context StorageContext) (bool, error) {
    sessionExpiresAtString, err := GetAuthFieldWithContext(context, SESSION_EXPIRES_AT_UNIX)
    if err != nil {
        return false, fmt.Errorf("get %s: %w", SESSION_EXPIRES_AT_UNIX, err)
    }
    sessionExpiresAtInt, err := strconv.Atoi(sessionExpiresAtString)
    if err != nil {
        return false, fmt.Errorf("parse session expiration value \"%s\": %w", sessionExpiresAtString, err)
    }
    sessionExpiresAt := time.Unix(int64(sessionExpiresAtInt), 0)
    now := time.Now()
    return now.After(sessionExpiresAt), nil
}

func GetAccessTokenWithContext(context StorageContext) (string, error) {
    accessToken, err := GetAuthFieldWithContext(context, ACCESS_TOKEN)
    if err != nil {
        return "", fmt.Errorf("get %s: %w", ACCESS_TOKEN, err)
    }
    if accessToken == "" {
        return "", fmt.Errorf("%s not set", ACCESS_TOKEN)
    }
    return accessToken, nil
}

func GetValidAccessTokenWithContext(p *print.Printer, context StorageContext) (string, error) {
    flow, err := GetAuthFlowWithContext(context)
    if err != nil {
        return "", fmt.Errorf("get authentication flow: %w", err)
    }

    if flow != AUTH_FLOW_USER_TOKEN {
        return "", fmt.Errorf("unsupported authentication flow: %s", flow)
    }

    // Load tokens from storage
    authFields := map[authFieldKey]string{
        ACCESS_TOKEN:       "",
        REFRESH_TOKEN:      "",
        IDP_TOKEN_ENDPOINT: "",
    }
    err = GetAuthFieldMapWithContext(context, authFields)
    if err != nil {
        return "", fmt.Errorf("get tokens from auth storage: %w", err)
    }

    accessToken := authFields[ACCESS_TOKEN]
    refreshToken := authFields[REFRESH_TOKEN]
    tokenEndpoint := authFields[IDP_TOKEN_ENDPOINT]

    if accessToken == "" {
        return "", fmt.Errorf("access token not set")
    }
    if refreshToken == "" {
        return "", fmt.Errorf("refresh token not set")
    }
    if tokenEndpoint == "" {
        return "", fmt.Errorf("token endpoint not set")
    }

    // Check if access token is expired
    accessTokenExpired, err := TokenExpired(accessToken)
    if err != nil {
        return "", fmt.Errorf("check if access token has expired: %w", err)
    }
    if !accessTokenExpired {
        return accessToken, nil
    }

    p.Debug(print.DebugLevel, "access token expired, refreshing...")

    // Create temporary userTokenFlow to refresh
    utf := &userTokenFlow{
        printer:       p,
        client:        &http.Client{},
        authFlow:      flow,
        accessToken:   accessToken,
        refreshToken:  refreshToken,
        tokenEndpoint: tokenEndpoint,
        context:       context, // NEW: pass context for storage
    }

    err = refreshTokens(utf)
    if err != nil {
        return "", fmt.Errorf("access token and refresh token expired: %w", err)
    }

    return utf.accessToken, nil
}
```

**Changes to `internal/pkg/auth/user_token_flow.go`:**

1. Add context field to `userTokenFlow` struct:
```go
type userTokenFlow struct {
    printer       *print.Printer
    client        *http.Client
    authFlow      AuthFlow
    accessToken   string
    refreshToken  string
    tokenEndpoint string
    context       StorageContext // NEW: storage context for this flow
}
```

2. Update `UserTokenFlow` to use context:
```go
func UserTokenFlow(p *print.Printer) http.RoundTripper {
    return UserTokenFlowWithContext(p, StorageContextCLI)
}

func UserTokenFlowWithContext(p *print.Printer, context StorageContext) http.RoundTripper {
    return &userTokenFlow{
        printer: p,
        client:  &http.Client{},
        context: context,
    }
}
```

3. Update `loadVarsFromStorage` to use context:
```go
func (u *userTokenFlow) loadVarsFromStorage() error {
    authFields := map[authFieldKey]string{
        ACCESS_TOKEN:       "",
        REFRESH_TOKEN:      "",
        IDP_TOKEN_ENDPOINT: "",
    }
    err := GetAuthFieldMapWithContext(u.context, authFields)
    if err != nil {
        return fmt.Errorf("get tokens from auth storage: %w", err)
    }
    // ... rest of the logic
}
```

4. Update `refreshTokens` to use context when storing:
```go
func refreshTokens(u *userTokenFlow) error {
    // ... token refresh logic ...

    // Store updated tokens using context
    err = SetAuthFieldWithContext(u.context, ACCESS_TOKEN, newAccessToken)
    if err != nil {
        return fmt.Errorf("set access token: %w", err)
    }

    err = SetAuthFieldWithContext(u.context, REFRESH_TOKEN, newRefreshToken)
    if err != nil {
        return fmt.Errorf("set refresh token: %w", err)
    }

    // ... rest of the logic
}
```

**Files Modified:**
- `internal/pkg/auth/auth.go` - Add context-aware token management functions
- `internal/pkg/auth/user_token_flow.go` - Add context support to token flow

### Phase 5: Testing and Documentation

**Goal:** Ensure the implementation works correctly and is well-documented

**Testing Tasks:**

1. **Manual Testing:**
   - [ ] Test `stackit auth provider login` - verify browser opens and credentials are stored
   - [ ] Verify credentials stored in separate keyring service (`stackit-cli-provider`)
   - [ ] Verify fallback to file storage when keyring unavailable
   - [ ] Test `stackit auth provider logout` - verify credentials are removed
   - [ ] Test `stackit auth provider get-access-token` - verify token is returned
   - [ ] Test `stackit auth provider status` - verify status is correct
   - [ ] Test token refresh - wait for token to expire and verify auto-refresh
   - [ ] Test with profiles - verify each profile has independent provider auth
   - [ ] Verify CLI auth (`stackit auth login`) is independent from provider auth

2. **Integration Testing:**
   - [ ] Test with STACKIT SDK (Go) - verify SDK can read provider credentials
   - [ ] Test with Terraform Provider - verify provider can read credentials
   - [ ] Test token refresh from SDK/Provider side
   - [ ] Test fallback behavior (keyring -> file)

3. **Unit Testing:**
   - [ ] Add tests for context-aware storage functions in `storage_test.go`
   - [ ] Add tests for `AuthorizeUserWithContext` in `user_login_test.go`
   - [ ] Add tests for context-aware token management in `auth_test.go`

**Documentation Tasks:**

1. **User Documentation:**
   - [ ] Add provider auth commands to CLI help text
   - [ ] Create usage guide for Terraform Provider integration
   - [ ] Create usage guide for SDK integration
   - [ ] Document the difference between CLI auth and provider auth
   - [ ] Add examples to command help text

2. **Developer Documentation:**
   - [ ] Document storage context architecture
   - [ ] Document token refresh mechanism
   - [ ] Add comments to new functions
   - [ ] Update architecture diagrams if they exist

### Phase 6: SDK/Terraform Provider Integration

**Goal:** Implement the consumption side in SDK and Terraform Provider

**Note:** This phase is outside the CLI repository but documented here for completeness.

**SDK Changes (stackit-sdk-go):**

1. Add new configuration option `WithCliAuth()`:
```go
package config

func WithCliAuth() ConfigurationOption {
    return func(c *Configuration) error {
        // Try to load credentials from keyring or file
        credentials, err := loadCliAuthCredentials()
        if err != nil {
            return fmt.Errorf("load CLI auth credentials: %w", err)
        }

        // Create a round tripper that handles token refresh
        rt := &cliAuthRoundTripper{
            credentials: credentials,
        }

        c.HTTPClient = &http.Client{
            Transport: rt,
        }

        return nil
    }
}

func loadCliAuthCredentials() (*cliAuthCredentials, error) {
    // 1. Try keyring first (service: stackit-cli-provider)
    accessToken, err := keyring.Get("stackit-cli-provider", "access_token")
    if err == nil {
        refreshToken, _ := keyring.Get("stackit-cli-provider", "refresh_token")
        tokenEndpoint, _ := keyring.Get("stackit-cli-provider", "idp_token_endpoint")
        return &cliAuthCredentials{
            AccessToken:   accessToken,
            RefreshToken:  refreshToken,
            TokenEndpoint: tokenEndpoint,
        }, nil
    }

    // 2. Fall back to file
    filePath := filepath.Join(os.Getenv("HOME"), ".stackit", "cli-provider-auth-storage.txt")
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("no CLI auth credentials found: %w", err)
    }

    // Decode and parse
    decoded, err := base64.StdEncoding.DecodeString(string(data))
    if err != nil {
        return nil, fmt.Errorf("decode credentials: %w", err)
    }

    var creds map[string]string
    err = json.Unmarshal(decoded, &creds)
    if err != nil {
        return nil, fmt.Errorf("parse credentials: %w", err)
    }

    return &cliAuthCredentials{
        AccessToken:   creds["access_token"],
        RefreshToken:  creds["refresh_token"],
        TokenEndpoint: creds["idp_token_endpoint"],
    }, nil
}
```

2. Implement token refresh in `cliAuthRoundTripper`:
```go
type cliAuthRoundTripper struct {
    credentials *cliAuthCredentials
    mu          sync.Mutex
}

func (c *cliAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Check if token is expired
    if c.tokenExpired() {
        err := c.refreshToken()
        if err != nil {
            return nil, fmt.Errorf("refresh token: %w", err)
        }
    }

    // Add bearer token to request
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.credentials.AccessToken))

    // Execute request
    return http.DefaultTransport.RoundTrip(req)
}
```

**Terraform Provider Changes (terraform-provider-stackit):**

1. Add `cli_auth` attribute to provider schema:
```hcl
provider "stackit" {
  cli_auth = true  # Enable CLI-based authentication
}
```

2. Implement CLI auth in provider configuration:
```go
func (p *stackitProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
    var config stackitProviderModel
    resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

    // If cli_auth is enabled, try to use it
    if config.CliAuth.ValueBool() {
        // Use SDK's WithCliAuth() option
        client, err := stackit.NewClient(
            stackit.WithCliAuth(),
        )
        if err != nil {
            // Fall back to other auth methods or error
        }
    }
    // ... rest of configuration
}
```

## Migration and Backward Compatibility

### Backward Compatibility

- All existing CLI commands and functionality remain unchanged
- Existing auth storage is not affected
- Existing `stackit auth login` continues to work exactly as before
- No breaking changes to any existing APIs

### User Migration

No migration required - this is a new opt-in feature:

1. Users continue using existing CLI auth for CLI operations
2. Users can optionally run `stackit auth provider login` for Terraform/SDK usage
3. Both authentications can coexist independently

## Security Considerations

1. **Credential Isolation:**
   - Provider credentials stored separately from CLI credentials
   - Separate keyring service names prevent accidental mixing
   - Separate file paths for fallback storage

2. **File Permissions:**
   - Fallback files created with `0o600` (owner read/write only)
   - Base64 encoding provides obfuscation (not encryption)
   - Keyring provides OS-level encryption where available

3. **Token Lifecycle:**
   - Access tokens are short-lived (typically 1 hour)
   - Refresh tokens used to obtain new access tokens
   - Session expiration forces re-authentication (default: 2 hours)

4. **Multi-User Systems:**
   - Each OS user has independent credentials
   - Keyring and file storage are user-specific
   - No cross-user credential access

## Success Criteria

1. **Functionality:**
   - [ ] Users can run `stackit auth provider login` to authenticate
   - [ ] Credentials are stored in keyring or file (with fallback)
   - [ ] SDK can read and use provider credentials
   - [ ] Terraform Provider can read and use provider credentials
   - [ ] Tokens are automatically refreshed when expired
   - [ ] Users can logout with `stackit auth provider logout`

2. **Separation:**
   - [ ] CLI auth and provider auth are completely independent
   - [ ] Different storage locations (keyring service and file path)
   - [ ] Users can be logged in to different accounts for CLI and provider

3. **User Experience:**
   - [ ] Clear error messages when auth is required
   - [ ] Simple login flow (one command)
   - [ ] Explicit opt-in (users must enable in Terraform/SDK)
   - [ ] Status command shows current auth state

4. **Quality:**
   - [ ] All new code has unit tests
   - [ ] Integration tests with SDK/Terraform Provider pass
   - [ ] Documentation is complete and clear
   - [ ] No regressions in existing functionality

## Timeline and Phases

**Phase 1-2:** Refactoring (Estimated: 3-5 days)
- Refactor storage layer
- Refactor user login flow
- Unit tests for refactored code

**Phase 3-4:** New Commands and Features (Estimated: 3-5 days)
- Implement provider auth commands
- Add context-aware token management
- Unit tests for new commands

**Phase 5:** Testing and Documentation (Estimated: 2-3 days)
- Manual testing
- Documentation updates
- Bug fixes

**Phase 6:** SDK/Provider Integration (Estimated: 5-7 days per repository)
- SDK implementation
- Terraform Provider implementation
- Integration testing

**Total Estimated Time:** 2-3 weeks for CLI, 1-2 weeks for SDK/Provider

## Open Questions

1. **Command Naming:**
   - Should it be `stackit auth provider` or `stackit auth terraform`?
   - Recommendation: `stackit auth provider` (more generic, covers SDK too)

2. **Session Time Limit:**
   - Should provider auth use the same session time limit as CLI auth?
   - Recommendation: Yes, read from same config key for consistency

3. **Profile Support:**
   - Should provider auth respect CLI profiles?
   - Recommendation: Yes, each profile has independent provider auth

4. **Environment Variables:**
   - Should we support `STACKIT_CLI_AUTH_DISABLE` to force-disable CLI auth in Terraform/SDK?
   - Recommendation: Yes, for security-conscious environments

5. **Beta Phase:**
   - Should this feature start as beta/experimental?
   - Recommendation: Yes, use `--experimental` flag or beta documentation

## Future Enhancements

1. **Multiple Provider Sessions:**
   - Allow multiple simultaneous provider auth sessions
   - Requires SDK/Provider to specify which session to use

2. **Python SDK Support:**
   - After Go SDK stabilizes, implement in Python SDK

3. **Service Account Support:**
   - Allow `stackit auth provider activate-service-account`
   - Store service account credentials in provider-specific storage

4. **Auto-Login:**
   - If provider auth is not set up, prompt user to login
   - Requires interactive terminal detection

## References

- Original Design Document: See context provided
- STACKIT CLI Repository: `github.com/stackitcloud/stackit-cli`
- STACKIT SDK Repository: `github.com/stackitcloud/stackit-sdk-go`
- Terraform Provider Repository: `github.com/stackitcloud/terraform-provider-stackit`
- Keyring Library: `github.com/zalando/go-keyring`
- OAuth2 Library: `golang.org/x/oauth2`

## Appendix A: File Structure

```
stackit-cli/
├── internal/
│   ├── cmd/
│   │   └── auth/
│   │       ├── auth.go (modified - add provider subcommand)
│   │       ├── login/
│   │       ├── logout/
│   │       ├── activate-service-account/
│   │       ├── get-access-token/
│   │       └── provider/ (NEW)
│   │           ├── provider.go (NEW)
│   │           ├── login.go (NEW)
│   │           ├── logout.go (NEW)
│   │           ├── get_access_token.go (NEW)
│   │           └── status.go (NEW)
│   └── pkg/
│       └── auth/
│           ├── storage.go (modified - add context support)
│           ├── user_login.go (modified - add context support)
│           ├── auth.go (modified - add context-aware functions)
│           ├── user_token_flow.go (modified - add context support)
│           ├── service_account.go (unchanged)
│           └── utils.go (unchanged)
├── PLAN.md (NEW - this document)
└── CLAUDE.md (NEW - codebase knowledge)
```

## Appendix B: Storage Schema

### CLI Auth Storage (Unchanged)

**Keyring Service:** `stackit-cli` (or `stackit-cli/{profile}`)
**File Path:** `~/.stackit/cli-auth-storage.txt` (or `~/.stackit/profiles/{profile}/cli-auth-storage.txt`)

**Fields:**
```json
{
  "auth_flow_type": "user_token",
  "access_token": "...",
  "refresh_token": "...",
  "user_email": "user@example.com",
  "session_expires_at_unix": "1234567890",
  "idp_token_endpoint": "https://..."
}
```

### Provider Auth Storage (NEW)

**Keyring Service:** `stackit-cli-provider` (or `stackit-cli-provider/{profile}`)
**File Path:** `~/.stackit/cli-provider-auth-storage.txt` (or `~/.stackit/profiles/{profile}/cli-provider-auth-storage.txt`)

**Fields:** (Same structure as CLI auth)
```json
{
  "auth_flow_type": "user_token",
  "access_token": "...",
  "refresh_token": "...",
  "user_email": "user@example.com",
  "session_expires_at_unix": "1234567890",
  "idp_token_endpoint": "https://..."
}
```
