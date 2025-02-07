//go:build integration

package provider

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/bastionzero/opk-ssh/internal/projectpath"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type ExampleOpContainer struct {
	testcontainers.Container
	Host string
	Port int
}

func RunExampleOpContainer(ctx context.Context, networkName string, env map[string]string, port string) (*ExampleOpContainer, error) {
	issuerServerPort := fmt.Sprintf("%s/tcp", port)
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       projectpath.Root,
			Dockerfile:    filepath.Join("test", "integration", "provider", "exampleop.Dockerfile"),
			PrintBuildLog: true,
			KeepImage:     true,
		},
		Env:          env,
		ExposedPorts: []string{issuerServerPort},
		Networks: []string{
			networkName,
		},
		ImagePlatform: "linux/amd64",
		WaitingFor: wait.ForHTTP("/.well-known/openid-configuration").
			WithPort(nat.Port(issuerServerPort)).
			WithStartupTimeout(10 * time.Second).
			WithMethod(http.MethodGet),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	mappedPort, err := container.MappedPort(ctx, nat.Port(issuerServerPort))
	if err != nil {
		return nil, err
	}
	hostIP, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}
	return &ExampleOpContainer{
		Container: container,
		Host:      hostIP,
		Port:      mappedPort.Int(),
	}, nil
}
