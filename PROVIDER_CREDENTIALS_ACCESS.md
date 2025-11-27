# Accessing STACKIT CLI Provider Credentials

This document describes how external applications (like the Terraform Provider) can read provider credentials stored by `stackit auth provider login` **without importing the CLI package** (to avoid dependency conflicts).

## Overview

The CLI stores provider credentials in two locations:
1. **Primary**: System keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
2. **Fallback**: Base64-encoded JSON file

External apps should try keyring first, then fall back to file.

## Credential Storage Locations

### Keyring

| Profile | Service Name | Account Names |
|---------|-------------|---------------|
| `default` | `stackit-cli-provider` | `access_token`, `refresh_token`, `user_email` |
| `dev` | `stackit-cli-provider/dev` | `access_token`, `refresh_token`, `user_email` |
| Custom profile | `stackit-cli-provider/{profile-name}` | `access_token`, `refresh_token`, `user_email` |

Additional account names available: `session_expires_at_unix`, `auth_flow_type`

### File (Fallback)

| Profile | File Path |
|---------|-----------|
| `default` | `~/.stackit/cli-provider-auth-storage.txt` |
| Custom profile | `~/.stackit/profiles/{profile-name}/cli-provider-auth-storage.txt` |

**File Format**: Base64-encoded JSON
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "user_email": "user@example.com",
  "session_expires_at_unix": "1732633200",
  "auth_flow_type": "user_token"
}
```

## Active Profile Detection

1. Check environment variable: `STACKIT_CLI_PROFILE`
2. If not set, read file: `~/.config/stackit/cli-profile.txt`
3. If file doesn't exist, use `"default"`

## Go Implementation

```go
package stackitcli

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/zalando/go-keyring"
)

// ProviderCredentials contains the credentials stored by stackit auth provider login
type ProviderCredentials struct {
    AccessToken  string
    RefreshToken string
    Email        string
}

// GetProviderCredentials reads provider credentials from keyring or file fallback
func GetProviderCredentials() (*ProviderCredentials, error) {
    // 1. Get active profile
    profile, err := getActiveProfile()
    if err != nil {
        return nil, fmt.Errorf("get active profile: %w", err)
    }

    // 2. Try keyring first
    creds, err := getFromKeyring(profile)
    if err == nil {
        return creds, nil
    }

    // 3. Fall back to file
    creds, err = getFromFile(profile)
    if err != nil {
        return nil, fmt.Errorf("credentials not found in keyring or file: %w", err)
    }

    return creds, nil
}

func getActiveProfile() (string, error) {
    // Check environment variable first
    if profile := os.Getenv("STACKIT_CLI_PROFILE"); profile != "" {
        return profile, nil
    }

    // Read from config file
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return "", fmt.Errorf("get home dir: %w", err)
    }

    profilePath := filepath.Join(homeDir, ".config", "stackit", "cli-profile.txt")
    data, err := os.ReadFile(profilePath)
    if err != nil {
        // File doesn't exist, use default profile
        if os.IsNotExist(err) {
            return "default", nil
        }
        return "", fmt.Errorf("read profile file: %w", err)
    }

    return strings.TrimSpace(string(data)), nil
}

func getKeyringServiceName(profile string) string {
    if profile == "default" {
        return "stackit-cli-provider"
    }
    return fmt.Sprintf("stackit-cli-provider/%s", profile)
}

func getFromKeyring(profile string) (*ProviderCredentials, error) {
    serviceName := getKeyringServiceName(profile)

    accessToken, err := keyring.Get(serviceName, "access_token")
    if err != nil {
        return nil, fmt.Errorf("get access_token: %w", err)
    }

    refreshToken, err := keyring.Get(serviceName, "refresh_token")
    if err != nil {
        return nil, fmt.Errorf("get refresh_token: %w", err)
    }

    email, err := keyring.Get(serviceName, "user_email")
    if err != nil {
        return nil, fmt.Errorf("get user_email: %w", err)
    }

    return &ProviderCredentials{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        Email:        email,
    }, nil
}

func getFromFile(profile string) (*ProviderCredentials, error) {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return nil, fmt.Errorf("get home dir: %w", err)
    }

    // Construct file path
    var filePath string
    if profile == "default" {
        filePath = filepath.Join(homeDir, ".stackit", "cli-provider-auth-storage.txt")
    } else {
        filePath = filepath.Join(homeDir, ".stackit", "profiles", profile, "cli-provider-auth-storage.txt")
    }

    // Read Base64-encoded content
    contentEncoded, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("read file: %w", err)
    }

    // Decode from Base64
    contentBytes, err := base64.StdEncoding.DecodeString(string(contentEncoded))
    if err != nil {
        return nil, fmt.Errorf("decode base64: %w", err)
    }

    // Parse JSON
    var data map[string]string
    if err := json.Unmarshal(contentBytes, &data); err != nil {
        return nil, fmt.Errorf("unmarshal json: %w", err)
    }

    // Extract credentials
    accessToken, ok := data["access_token"]
    if !ok || accessToken == "" {
        return nil, fmt.Errorf("access_token not found in file")
    }

    refreshToken, ok := data["refresh_token"]
    if !ok || refreshToken == "" {
        return nil, fmt.Errorf("refresh_token not found in file")
    }

    email, ok := data["user_email"]
    if !ok || email == "" {
        return nil, fmt.Errorf("user_email not found in file")
    }

    return &ProviderCredentials{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        Email:        email,
    }, nil
}
```

## Usage Example

```go
package main

import (
    "fmt"
    "net/http"
)

func main() {
    // Get credentials
    creds, err := GetProviderCredentials()
    if err != nil {
        fmt.Printf("No CLI credentials found: %v\n", err)
        fmt.Println("Please run: stackit auth provider login")
        return
    }

    // Use credentials in HTTP request
    req, _ := http.NewRequest("GET", "https://api.stackit.cloud/...", nil)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", creds.AccessToken))

    // ... make request
}
```

## Dependencies Required

The implementation above only requires:
- `github.com/zalando/go-keyring` (for keyring access)
- Go standard library

No other CLI dependencies needed.

## Token Refresh

If you need to refresh expired tokens, you'll need to implement the OAuth2 refresh flow yourself:

```go
import (
    "encoding/json"
    "net/http"
    "net/url"
    "strings"
)

func refreshToken(refreshToken string) (newAccessToken, newRefreshToken string, err error) {
    // IDP token endpoint
    tokenEndpoint := "https://accounts.stackit.cloud/oauth2/token"

    // Build request
    data := url.Values{}
    data.Set("grant_type", "refresh_token")
    data.Set("refresh_token", refreshToken)
    data.Set("client_id", "stackit-cli-0000-0000-000000000001")

    req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
    if err != nil {
        return "", "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    // Execute request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return "", "", err
    }
    defer resp.Body.Close()

    // Parse response
    var result struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", "", err
    }

    return result.AccessToken, result.RefreshToken, nil
}
```

## Writing Credentials Back (Optional)

If your app refreshes tokens, you can optionally write them back to storage for bidirectional sync. However, this adds complexity. It's usually better to let the CLI handle token refresh and just read the credentials when needed.

If you do need to write back:

```go
func writeToKeyring(profile string, creds *ProviderCredentials) error {
    serviceName := getKeyringServiceName(profile)

    if err := keyring.Set(serviceName, "access_token", creds.AccessToken); err != nil {
        return writeToFile(profile, creds)
    }

    keyring.Set(serviceName, "refresh_token", creds.RefreshToken)
    keyring.Set(serviceName, "user_email", creds.Email)

    return nil
}

func writeToFile(profile string, creds *ProviderCredentials) error {
    // Read existing file to preserve other fields
    homeDir, _ := os.UserHomeDir()
    var filePath string
    if profile == "default" {
        filePath = filepath.Join(homeDir, ".stackit", "cli-provider-auth-storage.txt")
    } else {
        filePath = filepath.Join(homeDir, ".stackit", "profiles", profile, "cli-provider-auth-storage.txt")
    }

    // Read and decode existing content
    contentEncoded, _ := os.ReadFile(filePath)
    contentBytes, _ := base64.StdEncoding.DecodeString(string(contentEncoded))

    var data map[string]string
    json.Unmarshal(contentBytes, &data)
    if data == nil {
        data = make(map[string]string)
    }

    // Update credentials
    data["access_token"] = creds.AccessToken
    data["refresh_token"] = creds.RefreshToken
    data["user_email"] = creds.Email

    // Encode and write
    newContent, _ := json.Marshal(data)
    encoded := base64.StdEncoding.EncodeToString(newContent)

    return os.WriteFile(filePath, []byte(encoded), 0600)
}
```

## Notes

- **Security**: Credentials are stored in the system keyring when available, with file fallback only when keyring is unavailable
- **Profiles**: The CLI supports multiple profiles. Always detect the active profile before reading credentials
- **Backwards Compatibility**: This storage format is stable and will be maintained across CLI versions
- **CLI vs Provider**: There are separate storage locations for CLI auth (`stackit-cli`) and Provider auth (`stackit-cli-provider`). Make sure to use the Provider storage locations as documented here.
