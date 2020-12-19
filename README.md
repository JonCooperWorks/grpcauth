# gRPCAuth
`github.com/joncooperworks/grpcauth` is a set of tested helpers for servers that authenticate clients using gRPC metadata using gRPC interceptors.
It supports permission based authentication, allowing users to limit a client's access to endpoints via permissions based on gRPC method names.
I use it in [wgrpcd](https://github.com/joncooperworks/wgrpcd) to authenticate `wgrpcd` clients and [wireguardhttps](https://github.com/joncooperworks/wireguardhttps) to authenticate against the `wgrpcd` instance.
It comes with helpers for [auth0 Machine to Machine](https://auth0.com/machine-to-machine) and [AWS Cognito App clients](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html) for both client and server side, but grpcauth is compatible with any authentication scheme

## Concepts

### Authority
An `Authority` allows a gRPC server to determine who is sending a request and check with an `AuthFunc` and an  optional `PermissionFunc` to determine if the authenticated client is allowed to interact with a particular gRPC method.
The `AuthFunc` allows callers can integrate any auth scheme.
By default, the Authority will take the method names as permission strings in the AuthResult.
See [cognito.go](./cognito.go) for an example.

### AuthFunc
An `AuthFunc` validates a gRPC request's metadata based on some arbitrary criteria.
It's meant to allow integration with a custom auth scheme.
Implementations should return error if authentication failed.
See [auth0.go](./auth0.go) and [cognito.go](./cognito.go) for examples.
```
type AuthFunc func(md metadata.MD) (*AuthResult, error)
```

### PermissionFunc
A `PermissionFunc` determines if an authenticated client is authorized to access a particular gRPC method.
It allows users to override the default permission behaviour that requires a permission with the full gRPC
method name be sent over during authentication.
See [permissions.go](./permissions.go) for an example.
```
type PermissionFunc func(permissions []string, methodName string) bool
```

### Client Credentials Grant Type
`github.com/joncooperworks/grpcauth` has Client Credentials flow helpers for [auth0](https://auth0.com/machine-to-machine) and [AWS Cognito](https://aws.amazon.com/cognito/).

## Other OAuth2
go-gRPC natively supports using an `oauth2.TokenSource` as a `grpc.DialOption` allowing any OpenID provider to be used to authenticate.
Simply implement an `AuthFunc` and optionally a `PermissionFunc` if you need custom permissions behaviour.