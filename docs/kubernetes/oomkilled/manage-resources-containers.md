---
title: Manage Resources for Containers
source: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
section: Memory Management and OOMKilled
doc_type: kubernetes_official
intended_use: rag
---

## Memory management and OOMKilled

Containers can be terminated if they exceed their memory limits.

When this happens, the container is killed and the reason is reported as `OOMKilled`.

### Resource requests and limits

Memory resources are specified using requests and limits:

```yaml
resources:
  requests:
    memory: "256Mi"
  limits:
    memory: "512Mi"
````

* `requests` are used for scheduling
* `limits` enforce the maximum memory usage

If a container exceeds its memory limit, it is terminated.

### Identifying OOMKilled containers

Use `kubectl describe pod` to check container termination reasons:

```text
Last State:     Terminated
  Reason:       OOMKilled
```

Increasing memory limits or optimizing application memory usage is required to resolve OOMKilled issues.

Restarting the Pod without changing resource limits does not solve the problem.

