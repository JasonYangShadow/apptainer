package oras

import (
	"context"
	"io"
	"net/http"

	"github.com/apptainer/apptainer/pkg/syfs"
	"github.com/apptainer/apptainer/pkg/sylog"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	ocitypes "github.com/containers/image/v5/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/schollz/progressbar/v3"
	oras_docker "oras.land/oras-go/pkg/auth/docker"
)

type resolver struct {
	remotes.Resolver
}

type pusher struct {
	remotes.Pusher
}

type contentWriter struct {
	content.Writer
	multiWriter io.Writer
}

func newResolver(options docker.ResolverOptions) remotes.Resolver {
	return &resolver{docker.NewResolver(options)}
}

func getOrasResolver(ctx context.Context, ociAuth *ocitypes.DockerAuthConfig, noHTTPS, push bool) (remotes.Resolver, error) {
	opts := docker.ResolverOptions{Credentials: genCredfn(ociAuth), PlainHTTP: noHTTPS}
	if ociAuth != nil && (ociAuth.Username != "" || ociAuth.Password != "") {
		return newResolver(opts), nil
	}

	cli, err := oras_docker.NewClient(syfs.DockerConf())
	if err != nil {
		sylog.Warningf("Couldn't load auth credential file: %s", err)
		return newResolver(opts), nil
	}
	httpClient := &http.Client{}

	if push {
		httpClient.Transport = newOrasUploadTransport()
	}

	solver, err := cli.Resolver(ctx, httpClient, noHTTPS)
	if err != nil {
		return &resolver{}, err
	}

	return &resolver{solver}, nil
}

func (r *resolver) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	return r.Resolver.Resolve(ctx, ref)
}

func (r *resolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return r.Resolver.Fetcher(ctx, ref)
}

func (r *resolver) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	p, err := r.Resolver.Pusher(ctx, ref)
	if err != nil {
		return &pusher{}, err
	}

	return &pusher{p}, nil
}

func (p *pusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	writer, err := p.Pusher.Push(ctx, desc)
	if err != nil {
		return &contentWriter{}, err
	}

	bar := progressbar.DefaultBytes(desc.Size)
	mwriter := io.MultiWriter(writer, bar)
	return &contentWriter{
		multiWriter: mwriter,
		Writer:      writer,
	}, nil
}

func (w *contentWriter) Write(p []byte) (n int, err error) {
	return w.multiWriter.Write(p)
}
