// Package grpcauth provides unary and stream grpc server interceptors that
// authenticate a gRPC client against various OAuth2 providers using the
// OAuth2 Client Credentials grant type.
// grpcauth has authenticators for the following providers:
// + auth0
// + AWS Cognito.
package grpcauth
