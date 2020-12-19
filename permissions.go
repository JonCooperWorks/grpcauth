package grpcauth

// PermissionFunc determines if an authenticated client is authorized to access a particular gRPC method.
// It allows users to override the default permission behaviour that requires a permission with the full gRPC
// method name be sent over during authentication.
type PermissionFunc func(permissions []string, methodName string) bool

// NoPermissions permits a gRPC client unlimited access to all methods on the server as long as they have no permissions.
// It allows for servers that grant authenticated clients access to all methods on a gRPC server.
// It will fail if a client has permissions.
func NoPermissions(permissions []string, methodName string) bool {
	if len(permissions) != 0 {
		return false
	}
	return true
}

func defaultHasPermissions(permissions []string, methodName string) bool {
	for _, permission := range permissions {
		if permission == methodName {
			return true
		}
	}

	return false
}
