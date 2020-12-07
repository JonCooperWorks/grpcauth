package grpcauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	targetMethodName = "/server.ServiceName/MethodName"
	testClientName   = "testClient"
)

var (
	testPermissionedAuthResult = &AuthResult{
		ClientIdentifier: testClientName,
		Permissions:      []string{targetMethodName},
	}
	testUnpermissionedAuthResult = &AuthResult{
		ClientIdentifier: testClientName,
		Permissions:      []string{},
	}
	testTargetMethodInfo = &grpc.UnaryServerInfo{
		FullMethod: targetMethodName,
	}
)

func TestDefaultPermissionsImplementation(t *testing.T) {
	authority := &authority{}
	if !authority.isAuthorized(testPermissionedAuthResult, testTargetMethodInfo.FullMethod) {
		t.Fatalf("Expected client to be authorized to access gRPC method")
	}

	if authority.isAuthorized(testUnpermissionedAuthResult, testTargetMethodInfo.FullMethod) {
		t.Fatalf("Expected client not to be authorized")
	}
}

// TestNoPermissionsImplementation also tests that Authority delegates permission validation to HasPermissions when one is provided.
func TestNoPermissionsImplementation(t *testing.T) {
	authority := &authority{HasPermissions: NoPermissions}
	if !authority.isAuthorized(testPermissionedAuthResult, testTargetMethodInfo.FullMethod) {
		t.Fatalf("Expected client to be authorized to access gRPC method")
	}

	if !authority.isAuthorized(testUnpermissionedAuthResult, testTargetMethodInfo.FullMethod) {
		t.Fatalf("Expected client to be authorized")
	}
}

func TestGetAuthResult(t *testing.T) {
	ctx := context.TODO()
	_, err := GetAuthResult(ctx)
	if err == nil {
		t.Fatalf("Expected error calling GetAuthResult with empty context")
	}

	if !errors.Is(err, ErrUnauthenticatedContext) {
		t.Fatalf("Unexpected error type")
	}

	k := authContextKey("auth")
	ctx = context.WithValue(ctx, k, testPermissionedAuthResult)
	result, err := GetAuthResult(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !reflect.DeepEqual(result, testPermissionedAuthResult) {
		t.Fatalf("Expected %+v, got %+v", testPermissionedAuthResult, result)
	}
}

func TestAuthenticateAndAuthorizeRejectsInvalidContextByDefault(t *testing.T) {
	ctxNoMetadata := context.TODO()
	md := metadata.Pairs("header", "notauth")
	ctxNoAuthHeader := metadata.NewIncomingContext(context.Background(), md)
	ctxs := []context.Context{
		ctxNoMetadata,
		ctxNoAuthHeader,
	}

	authority := &authority{}
	for _, ctx := range ctxs {
		_, err := authority.authenticateAndAuthorizeContext(ctx, targetMethodName)
		if err == nil {
			t.Fatalf("expected error with invalid context")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("authenticateAndAuthorizeContext must return a gRPC status for all errors")
		}

		if st.Code() != codes.Unauthenticated {
			t.Fatalf("expected unauthenticated, got %v", st.Code())
		}

		if st.Message() != UnauthenticatedError {
			t.Fatalf("expected unauthenticated error, got %v", st.Message())
		}
	}
}

func TestAuthorityRejectsFailedAuthAttempts(t *testing.T) {
	authority := &authority{IsAuthenticated: alwaysUnauthenticated}

	md := metadata.Pairs("authorization", "bearer words")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, err := authority.authenticateAndAuthorizeContext(ctx, targetMethodName)
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("authenticateAndAuthorizeContext must return a gRPC status for all errors")
	}

	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", st.Code())
	}

	if st.Message() != UnauthenticatedError {
		t.Fatalf("expected unauthenticated error, got %v", st.Message())
	}
}

func TestContextWithCorrectPermissionsAccepted(t *testing.T) {
	authority := &authority{IsAuthenticated: alwaysAuthenticatedAllPermissions}

	md := metadata.Pairs("authorization", "bearer words")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, err := authority.authenticateAndAuthorizeContext(ctx, targetMethodName)
	if err != nil {
		t.Fatal(err)
	}

	authResult, err := GetAuthResult(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if authResult.ClientIdentifier != testClientName {
		t.Fatalf("invalid client name, expected %v got %v", testClientName, authResult.ClientIdentifier)
	}
}

func alwaysAuthenticatedAllPermissions(md metadata.MD) (*AuthResult, error) {
	return &AuthResult{
		ClientIdentifier: testClientName,
		Timestamp:        time.Now(),
		Permissions:      []string{targetMethodName},
	}, nil
}

func alwaysAuthenticatedNoPermissions(md metadata.MD) (*AuthResult, error) {
	return &AuthResult{
		ClientIdentifier: testClientName,
		Timestamp:        time.Now(),
		Permissions:      []string{targetMethodName},
	}, nil
}

func alwaysUnauthenticated(md metadata.MD) (*AuthResult, error) {
	return nil, errors.New("unauthenticated")
}
