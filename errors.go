package grpcauth

// PermissionDeniedError is a JSON object containing the error details to help a client debug permission errors.
// This is included in the gRPC error response.
type PermissionDeniedError struct {
	ClientIdentifier    string   `json:"clientIdentifier"`
	PermissionRequested string   `json:"permissionRequested"`
	ClientPermissions   []string `json:"clientPermissions"`
}

// UnauthenticatedError is a JSON object returned when a gRPC client attempts to access the server without authenticating.
// Since the user hasn't authenticated, don't even marshal a struct: just return this const string.
const UnauthenticatedError = `{"error": "no valid authorzation metadata field"}`
