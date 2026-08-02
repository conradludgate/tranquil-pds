# Publishing the SQLite image to GHCR

The `megamerge` branch publishes a multi-architecture image to:

```text
ghcr.io/conradludgate/tranquil-pds:sqlite
```

The workflow also publishes a commit-specific `sqlite-<sha>` tag. Use the
commit-specific tag while testing, then pin the resulting image digest in the
Flux deployment before calling the cluster production-ready.

The package must be made public in the repository's GitHub Packages settings if
the k3s node should pull it without an image-pull secret. If it remains private,
create a read-only GitHub fine-grained token and configure an image-pull secret
in the cluster; never commit that secret.
