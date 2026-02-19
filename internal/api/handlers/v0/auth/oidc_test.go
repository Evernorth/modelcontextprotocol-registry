package auth_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/registry/internal/api/handlers/v0/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockGenericOIDCValidator for testing
type MockGenericOIDCValidator struct {
	validateFunc func(ctx context.Context, token string) (*auth.OIDCClaims, error)
}

func (m *MockGenericOIDCValidator) ValidateToken(ctx context.Context, token string) (*auth.OIDCClaims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, fmt.Errorf("not implemented")
}

func TestOIDCHandler_ExchangeToken(t *testing.T) {
	tests := []struct {
		name          string
		config        *config.Config
		mockValidator *MockGenericOIDCValidator
		token         string
		expectedError bool
	}{
		{
			name: "successful token exchange with publish permissions",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"hd":"modelcontextprotocol.io"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // 32 byte hex
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"email":              "admin@modelcontextprotocol.io",
							"email_verified":     true,
							"hd":                 "modelcontextprotocol.io",
							"preferred_username": "admin",
						},
					}, nil
				},
			},
			token:         "valid-oidc-token",
			expectedError: false,
		},
		{
			name: "failed validation with invalid hosted domain",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"hd":"modelcontextprotocol.io"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"email":              "user@example.com",
							"email_verified":     true,
							"hd":                 "example.com", // Wrong domain
							"preferred_username": "user",
						},
					}, nil
				},
			},
			token:         "invalid-domain-token",
			expectedError: true,
		},
		{
			name: "successful validation with extra claim 'client_id'",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://cigna.oktapreview.com",
				OIDCClientID:     "api://glbcore",
				OIDCExtraClaims:  `[{"client_id":"matched_client_id_value"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						Subject: "user-subject-123",
						ExtraClaims: map[string]any{
							"email":     "user@cigna.com",
							"client_id": "matched_client_id_value",
						},
					}, nil
				},
			},
			token:         "valid-okta-token",
			expectedError: false,
		},
		{
			name: "failed validation with wrong extra claim 'client_id'",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://cigna.oktapreview.com",
				OIDCClientID:     "api://glbcore",
				OIDCExtraClaims:  `[{"client_id":"client_id_value"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						Subject: "user-subject-123",
						ExtraClaims: map[string]any{
							"email":     "user@cigna.com",
							"client_id": "wrong_client_id_value",
						},
					}, nil
				},
			},
			token:         "invalid-client-id-token",
			expectedError: true,
		},
		{
			name: "successful validation with array claim - scalar expected value in array",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"groups":"admin"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"groups": []any{"admin", "users", "developers"},
						},
					}, nil
				},
			},
			token:         "valid-array-claim-token",
			expectedError: false,
		},
		{
			name: "failed validation with array claim - scalar not in array",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"groups":"super-admin"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"groups": []any{"admin", "users", "developers"},
						},
					}, nil
				},
			},
			token:         "invalid-array-claim-token",
			expectedError: true,
		},
		{
			name: "successful validation with array to array comparison - overlapping values",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"roles":["admin","moderator"]}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"roles": []any{"admin", "users"},
						},
					}, nil
				},
			},
			token:         "valid-array-array-token",
			expectedError: false,
		},
		{
			name: "failed validation with array to array comparison - no overlapping values",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"roles":["super-admin","owner"]}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"roles": []any{"admin", "users"},
						},
					}, nil
				},
			},
			token:         "invalid-array-array-token",
			expectedError: true,
		},
		{
			name: "successful validation with single-element array normalization",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"department":"engineering"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"department": []any{"engineering"}, // Single element array
						},
					}, nil
				},
			},
			token:         "valid-single-array-token",
			expectedError: false,
		},
		{
			name: "failed validation with missing claim",
			config: &config.Config{
				OIDCEnabled:      true,
				OIDCIssuer:       "https://accounts.google.com",
				OIDCClientID:     "test-client-id",
				OIDCExtraClaims:  `[{"required_claim":"expected_value"}]`,
				OIDCPublishPerms: "*",
				JWTPrivateKey:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			mockValidator: &MockGenericOIDCValidator{
				validateFunc: func(_ context.Context, _ string) (*auth.OIDCClaims, error) {
					return &auth.OIDCClaims{
						ExtraClaims: map[string]any{
							"other_claim": "some_value",
						},
					}, nil
				},
			},
			token:         "missing-claim-token",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := auth.NewOIDCHandler(tt.config)
			if tt.mockValidator != nil {
				handler.SetValidator(tt.mockValidator)
			}

			ctx := context.Background()
			response, err := handler.ExchangeToken(ctx, tt.token)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.NotEmpty(t, response.RegistryToken)
				assert.Greater(t, response.ExpiresAt, 0)
			}
		})
	}
}
