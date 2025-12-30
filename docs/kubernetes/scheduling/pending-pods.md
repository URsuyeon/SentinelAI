---
title: Pod Scheduling and Pending State
source: https://kubernetes.io/docs/concepts/scheduling-eviction/pod-scheduling/
section: Pending Pods
doc_type: kubernetes_official
intended_use: rag
---

## Pending Pods

A Pod is in the `Pending` state when it has been accepted by the Kubernetes system but has not been scheduled to a node.

### Common reasons for Pending Pods

- Insufficient CPU or memory on available nodes
- Node selectors or affinity rules cannot be satisfied
- Required PersistentVolume is not available

### Debugging Pending Pods

Use `kubectl describe pod` to inspect scheduling events:

```bash
kubectl describe pod <pod-name>
````

Example event:

```text
0/3 nodes are available: 3 Insufficient memory.
```

Scheduling issues must be resolved before the Pod can transition to the `Running` state.
