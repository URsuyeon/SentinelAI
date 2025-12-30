---
title: ErrImagePull
source: https://kubernetes.io/docs/concepts/containers/images/
section: ErrImagePull
doc_type: kubernetes_official
intended_use: rag
---

## ErrImagePull

`ErrImagePull` indicates that Kubernetes attempted to pull a container image but failed.

This error typically appears before the Pod transitions to `ImagePullBackOff`.

### Typical reasons for ErrImagePull

- Image does not exist in the registry
- Invalid image tag
- Registry authentication failure
- Registry is unreachable from the node

### Inspect the error message

Use `kubectl describe pod` to view detailed error messages:

```bash
kubectl describe pod <pod-name>
````

Example output:

```text
Failed to pull image "myrepo/myimage:v1":
rpc error: code = Unknown desc = Error response from daemon
```

The error message often provides the exact cause, such as authentication failure or missing image.

### Difference between ErrImagePull and ImagePullBackOff

* `ErrImagePull` indicates an immediate image pull failure
* `ImagePullBackOff` indicates repeated failures with backoff retries

Understanding this distinction helps determine whether the issue is transient or persistent.

### Common debugging steps

* Verify the image name and tag
* Check image pull secrets
* Confirm registry availability
* Ensure the node has network access to the registry
