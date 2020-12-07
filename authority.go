package grpcauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
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

	// Callers cannot put the auth value into the context themselves, so it's safe to panic here.
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
type PermissionFunc func(permissions []string, methodnName string) bool

// NoPermissions permits a gRPC client unlimited access to all methods on the server.
// It allows for servers that grant authenticated clients access to all methods on a gRPC server.
func NoPermissions(permissions []string, methodName string) bool {
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
	HasPermissions  func(permissions []string, methodName string) bool
	Logger          *log.Logger
}

// UnaryServerInterceptor ensures a request is authenticated based on its metadata before invoking the server handler.
func (a *Authority) UnaryServerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := a.authenticateAndAuthorizeContext(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

// StreamServerInterceptor authenticates stream requests.
func (a *Authority) StreamServerInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := a.authenticateAndAuthorizeContext(stream.Context(), info.FullMethod)
	if err != nil {
		return err
	}

	wrapped := grpc_middleware.WrapServerStream(stream)
	wrapped.WrappedContext = ctx
	return handler(srv, wrapped)
}

func (a *Authority) authenticateAndAuthorizeContext(ctx context.Context, methodName string) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errUnauthorized
	}

	authResult, err := a.IsAuthenticated(md)
	if err != nil {
		a.logf("Error authorizing user: %v", err)
		return nil, errUnauthorized
	}
	a.logf("Successfully authenticated client with identifier '%s' and permissions: %+v", authResult.ClientIdentifier, authResult.Permissions)
	// Insert auth result into the context so handlers can determine which client is performing an action.
	authKey := authContextKey(authKeyName)
	ctx = context.WithValue(ctx, authKey, authResult)

	if a.isAuthorized(authResult, methodName) {
		a.logf("Client '%s' does not have permission to access method '%s'", authResult.ClientIdentifier, methodName)
		permissionDenied := &PermissionDeniedError{
			ClientIdentifier:    authResult.ClientIdentifier,
			PermissionRequested: methodName,
			ClientPermissions:   authResult.Permissions,
		}

		b, err := json.Marshal(permissionDenied)
		if err != nil {
			a.logf("Error unmarshalling JSON: %v", err)
		}

		permissionDeniedJSON := string(b)
		return nil, status.Errorf(codes.PermissionDenied, permissionDeniedJSON)
	}

	return ctx, nil
}

func (a *Authority) logf(format string, args ...interface{}) {
	if a.Logger != nil {
		a.Logger.Printf(format, args...)
	}
}

func (a *Authority) isAuthorized(user *AuthResult, methodName string) bool {
	if a.HasPermissions == nil {
		return defaultHasPermissions(user.Permissions, methodName)
	}
	return a.HasPermissions(user.Permissions, methodName)
}

func defaultHasPermissions(permissions []string, methodName string) bool {
	for _, permission := range permissions {
		if permission == methodName {
			return true
		}
	}

	return false
}
