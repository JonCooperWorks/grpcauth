package grpcauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authKeyName = "auth"
)

var (
	errUnauthorized = status.Errorf(codes.Unauthenticated, UnauthenticatedError)
)

var (
	// ErrUnauthenticatedContext is returned from GetAuthResult when it is called with an unauthenticated context.
	ErrUnauthenticatedContext = fmt.Errorf("cannot get AuthResult from unauthenticated context")
)

// GetAuthResult is a helper function that returns the AuthResult attached to a context and returns ErrUnauthenticatedContext if none exists.
func GetAuthResult(ctx context.Context) (*AuthResult, error) {
	k := authContextKey(authKeyName)
	v := ctx.Value(k)
	if v == nil {
		return nil, ErrUnauthenticatedContext
	}

	return v.(*AuthResult), nil
}

// AuthFunc validates a gRPC request's metadata based on some arbitrary criteria.
// It's meant to allow integration with a custom auth scheme.
// Implementations should return error if authentication failed.
// See auth0.go and cognito.go.
type AuthFunc func(md metadata.MD) (*AuthResult, error)

// PermissionFunc determines if an authenticated client is authorized to access a particular gRPC method.
// It allows users to override the default permission behaviour that requires a permission with the full gRPC
// method name be sent over during authentication.
type PermissionFunc func(permissions []string, info *grpc.UnaryServerInfo) bool

// NoPermissions permits a gRPC client unlimited access to all methods on the server.
// It allows for servers that grant authenticated clients access to all methods on a gRPC server.
func NoPermissions(permissions []string, info *grpc.UnaryServerInfo) bool {
	return true
}

// authContextKey is a key for values injected into the context by an Authority's UnaryInterceptor.
type authContextKey string

// AuthResult is the result of authenticating a user.
type AuthResult struct {
	ClientIdentifier string
	Timestamp        time.Time
	Permissions      []string
}

// Authority allows a gRPC server to determine who is sending a request and check with an AuthFunc and an
// optional PermissionFunc if the client is allowed to interact with it.
// We delegate authentication to the IsAuthenticated function so callers can integrate any auth scheme.
// The optional HasPermissions function allows users to define custom behaviour for permission strings.
// By default, the Authority will take the method names as permission strings in the AuthResult.
// See cognito.go for an example.
// We log failed authentication attempts with the error message if a Logger is passed to an Authority.
type Authority struct {
	IsAuthenticated func(md metadata.MD) (*AuthResult, error)
	HasPermissions  func(permissions []string, info *grpc.UnaryServerInfo) bool
	Logger          *log.Logger
}

// UnaryInterceptor ensures a request is authenticated based on its metadata before invoking the server handler.
func (a *Authority) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errUnauthorized
	}

	authResult, err := a.IsAuthenticated(md)
	if err != nil {
		a.logf("Error authorizing user: %v", err)
		return nil, errUnauthorized
	}

	if a.isAuthorized(authResult, info) {
		a.logf("Client '%s' does not have permission to access method '%s'", authResult.ClientIdentifier, info.FullMethod)
		permissionDenied := &PermissionDeniedError{
			ClientIdentifier:    authResult.ClientIdentifier,
			PermissionRequested: info.FullMethod,
			ClientPermissions:   authResult.Permissions,
		}

		b, err := json.Marshal(permissionDenied)
		if err != nil {
			a.logf("Error unmarshalling JSON: %v", err)
		}

		permissionDeniedJSON := string(b)
		return nil, status.Errorf(codes.PermissionDenied, permissionDeniedJSON)
	}

	a.logf("Successfully authenticated client with identifier '%s' and permissions: %+v", authResult.ClientIdentifier, authResult.Permissions)

	// Insert auth result into the context so handlers can determine which client is performing an action.
	authKey := authContextKey(authKeyName)
	ctx = context.WithValue(ctx, authKey, authResult)
	return handler(ctx, req)
}

func (a *Authority) logf(format string, args ...interface{}) {
	if a.Logger != nil {
		a.Logger.Printf(format, args...)
	}
}

func (a *Authority) isAuthorized(user *AuthResult, info *grpc.UnaryServerInfo) bool {
	if a.HasPermissions == nil {
		return defaultHasPermissions(user.Permissions, info)
	}
	return a.HasPermissions(user.Permissions, info)
}

func defaultHasPermissions(permissions []string, info *grpc.UnaryServerInfo) bool {
	for _, permission := range permissions {
		if permission == info.FullMethod {
			return true
		}
	}

	return false
}
