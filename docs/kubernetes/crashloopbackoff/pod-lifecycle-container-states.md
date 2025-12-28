---
title: Pod Lifecycle and Container States
source: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
section: Container States
doc_type: kubernetes_official
intended_use: rag
---

## Container States

Once a Pod is scheduled to a node, the kubelet manages the containers and reports their states.

Each container in a Pod can be in one of the following states.

### Waiting

A container is in the `Waiting` state if it has not yet started running.

Reasons for a container being in this state include:

- Pulling the container image
- Waiting for a dependent service
- Applying container configuration

The reason for the waiting state is shown in the Pod status.

### Running

A container is in the `Running` state when it has been started and is executing normally.

If a container is running but later terminates, Kubernetes records the termination details.

### Terminated

A container enters the `Terminated` state when it has finished execution or has been stopped.

Common termination reasons include:

- The container process exited with a non-zero exit code
- The container was killed due to a resource limit (for example, OOMKilled)
- The container was terminated by the kubelet

Termination information includes:

- Exit code
- Signal
- Reason

Repeated transitions from `Terminated` back to `Running` can result in a `CrashLoopBackOff` Pod status.
