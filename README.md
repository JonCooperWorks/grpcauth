# grpcauth
`github.com/joncooperworks/grpcauth` is a set of tested helpers for servers that authenticate clients using gRPC metadata using gRPC interceptors.
It supports permission based authentication, allowing users to limit a client's access to endpoints via permissions based on gRPC method names.
I use it in [wgrpcd](https://github.com/joncooperworks/wgrpcd) to authenticate `wgrpcd` clients and [wireguardhttps](https://github.com/joncooperworks/wireguardhttps) to authenticate against the `wgrpcd` instance.
It comes with helpers for [auth0 Machine to Machine](https://auth0.com/machine-to-machine) and [AWS Cognito App clients](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html) for both client and server side, but grpcauth is compatible with any authentication scheme

## Concepts

### Authority
`github.com/joncooperworks/grpcauth` is centered around the `grpcauth.Authority` struct.


```
// Authority allows a gRPC server to determine who is sending a request with an AuthFunc and check with a PermissionFunc if the client is allowed to interact with it.
// We delegate authentication to the IsAuthenticated function so users can integrate any custom auth scheme.
// The HasPermissions function allows users to define custom behaviour for permission strings.
// By default, the Authority will take the method names as permission strings in the AuthResult.
// See cognito.go for an example.
// We log failed authentication attempts with the error message if a Logger is passed to an Authority.
type Authority struct {
	IsAuthenticated func(md metadata.MD) (*AuthResult, error)
	HasPermissions  func(permissions []string, info *grpc.UnaryServerInfo) bool
	Logger          *log.Logger
}

```

An Authority delegates authentication to a `grpcauth.AuthFunc` and authorization to a `grpcauth.PermissionFunc` to determine if a gRPC client is allowed to access a particular method on the server.
By default, the Authority expects the authenticated entity to have permissions that match the full names of the gRPC methods they intend to call.

### AuthFunc

### PermissionFunc

## OAuth2

### Client Credentials Grant Type
`github.com/joncooperworks/grpcauth` has Client Credentials flow helpers for [auth0](https://auth0.com/machine-to-machine) and [AWS Cognito](https://aws.amazon.com/cognito/).

#### AWS Cognito

#### Auth0

## Other OAuth2
go-gRPC natively supports using an `oauth2.TokenSource` as a `grpc.DialOption` allowing any OpenID provider to be used to authenticate.
Simply implement an `AuthFunc` and optionally a `PermissionFunc` if you need custom permissions behaviour.

## Other Auth Schemes