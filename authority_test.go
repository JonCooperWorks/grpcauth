package grpcauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

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
)

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
	authority := &authority{
		IsAuthenticated: alwaysAuthenticatedAllPermissions,
		HasPermissions:  defaultHasPermissions,
	}
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

func TextContextNoPermissionsWorksAsExpected(t *testing.T) {
	authority := &authority{
		IsAuthenticated: alwaysAuthenticatedNoPermissions,
		HasPermissions:  NoPermissions,
	}
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

func TestContextWithIncorrectPermissionsRejected(t *testing.T) {
	authority := &authority{
		IsAuthenticated: alwaysAuthenticatedNoPermissions,
		HasPermissions:  defaultHasPermissions,
	}

	md := metadata.Pairs("authorization", "bearer words")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, err := authority.authenticateAndAuthorizeContext(ctx, targetMethodName)
	if err == nil {
		t.Fatalf("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("authenticateAndAuthorizeContext must return a gRPC status for all errors")
	}

	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", st.Code())
	}

	const expectedMessage = `{"clientIdentifier":"testClient","permissionRequested":"/server.ServiceName/MethodName","clientPermissions":null}`
	if st.Message() != expectedMessage {
		t.Fatalf("expected %v, got %v", expectedMessage, st.Message())
	}

}

func TestContextWithPermissionsRejectedWhenServerIsNoPermissions(t *testing.T) {
	authority := &authority{
		IsAuthenticated: alwaysAuthenticatedAllPermissions,
		HasPermissions:  NoPermissions,
	}

	md := metadata.Pairs("authorization", "bearer words")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, err := authority.authenticateAndAuthorizeContext(ctx, targetMethodName)
	if err == nil {
		t.Fatalf("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("authenticateAndAuthorizeContext must return a gRPC status for all errors")
	}

	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", st.Code())
	}

	const expectedMessage = `{"clientIdentifier":"testClient","permissionRequested":"/server.ServiceName/MethodName","clientPermissions":["/server.ServiceName/MethodName"]}`
	if st.Message() != expectedMessage {
		t.Fatalf("expected %v, got %v", expectedMessage, st.Message())
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
	}, nil
}

func alwaysUnauthenticated(md metadata.MD) (*AuthResult, error) {
	return nil, errors.New("unauthenticated")
}
