---
title: ImagePullBackOff
source: https://kubernetes.io/docs/concepts/containers/images/
section: ImagePullBackOff
doc_type: kubernetes_official
intended_use: rag
---

## ImagePullBackOff

A Pod enters the `ImagePullBackOff` state when Kubernetes is unable to pull the container image and backs off from retrying.

This state usually follows one or more `ErrImagePull` errors.

### Common causes of ImagePullBackOff

- The container image name or tag is incorrect
- The image does not exist in the container registry
- The node does not have permission to pull the image
- Network connectivity issues to the container registry
- Image pull secrets are missing or misconfigured

### Check Pod events

Use `kubectl describe pod` to inspect image pull errors:

```bash
kubectl describe pod <pod-name>
````

Example event output:

```text
Failed to pull image "myrepo/myimage:latest": image not found
Back-off pulling image "myrepo/myimage:latest"
```

The `Back-off pulling image` message indicates that Kubernetes is retrying with increasing delay.

### Verify image name and tag

Ensure the image name and tag specified in the Pod spec are correct:

```yaml
containers:
- name: app
  image: myrepo/myimage:latest
```

A typo in the repository name or tag commonly causes ImagePullBackOff.

### Private registries and authentication

If the image is stored in a private registry, an image pull secret is required:

```yaml
imagePullSecrets:
- name: regcred
```

Verify that the secret exists in the same namespace as the Pod.