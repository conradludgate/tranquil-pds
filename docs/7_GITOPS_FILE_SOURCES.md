# GitOps file sources

Tranquil can reconcile JSON files mounted into the PDS into records in local
accounts. This is intended for Flux-managed ConfigMaps and similar GitOps
workflows. The reconciler polls each source directory; it does not depend on
filesystem notifications, which are unreliable for Kubernetes ConfigMap
volume updates.

Enable it with the following configuration:

```toml
[gitops]
scan_interval_secs = 30
sources = [
  "blog|/var/lib/tranquil-pds/gitops/blog|did:plc:example",
  "notes|/var/lib/tranquil-pds/gitops/notes|did:plc:example",
]
```

Each source has a stable name, a mounted directory, and one target DID. A DID
may have any number of sources. The directory layout is:

```text
<source>/
└── app.example.record/
    └── record-key.json
```

The JSON object must have a `$type` matching its directory collection. Known
lexicons are validated normally; arbitrary lexicons are accepted when their
record preamble is valid. Files with other extensions are ignored, but JSON
files outside the exact `collection/rkey.json` layout fail the scan.

Tranquil stores source ownership in `gitops_sources` and `gitops_records`. It
uses that ownership to make deletion safe:

- a source cannot overwrite a record already managed by another source;
- a source cannot overwrite or delete a record that changed outside GitOps;
- a missing file deletes its record only when the stored CID still matches;
- a failed or incomplete scan never performs deletion;
- changing a source's DID while it still owns records is rejected.

The SQLite and PostgreSQL backends include the ownership migration. The
feature is disabled when `gitops.sources` is empty. The embedded
`tranquil-store` backend does not currently provide the ownership repository,
so it logs a warning and leaves GitOps disabled if sources are configured.

## Flux and ConfigMaps

Mount every source in its own directory and configure the matching source
spec. For example:

```yaml
env:
  - name: GITOPS_SCAN_INTERVAL_SECS
    value: "30"
  - name: GITOPS_SOURCES
    value: blog|/var/lib/tranquil-pds/gitops/blog|did:plc:example
volumeMounts:
  - name: gitops-blog
    mountPath: /var/lib/tranquil-pds/gitops/blog
    readOnly: true
volumes:
  - name: gitops-blog
    configMap:
      name: tranquil-pds-gitops-blog
```

ConfigMap volumes are limited to roughly 1 MiB. For larger sources, split the
content into multiple ConfigMaps/sources or use a different mounted artifact.
ConfigMap keys must be mapped to nested paths when necessary so the resulting
volume preserves `collection/rkey.json`.
