package grpcauth

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc"
)

var (
	testPermissionedAuthResult = &AuthResult{
		ClientIdentifier: "testClient",
		Permissions:      []string{"/server.ServiceName/MethodName"},
	}
	testUnpermissionedAuthResult = &AuthResult{
		ClientIdentifier: "testClient",
		Permissions:      []string{},
	}
	testTargetMethodInfo = &grpc.UnaryServerInfo{
		FullMethod: "/server.ServiceName/MethodName",
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
