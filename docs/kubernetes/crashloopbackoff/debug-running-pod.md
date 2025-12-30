---
title: Debug Running Pods
source: https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/
section: Pod in CrashLoopBackOff
doc_type: kubernetes_official
intended_use: rag
---

## Pod in CrashLoopBackOff

A Pod enters the `CrashLoopBackOff` state when one of its containers repeatedly terminates and the kubelet restarts it.

This typically indicates that the container starts, fails shortly after, and is restarted in a loop.

### Check the Pod status

To see the current status of a Pod:

```bash
kubectl get pod <pod-name>
````

Example output:

```text
NAME        READY   STATUS             RESTARTS   AGE
nginx-pod  0/1     CrashLoopBackOff   5          10m
```

### Describe the Pod

Use `kubectl describe` to inspect detailed information about the Pod, including events and container states:

```bash
kubectl describe pod <pod-name>
```

In the output, check the **Last State** section of the container:

```text
Last State:     Terminated
  Reason:       Error
  Exit Code:    1
```

The exit code and reason can help identify why the container terminated.

### View logs from the previous container instance

When a container crashes and restarts, the logs of the previous instance are not shown by default.

Use the `--previous` flag to retrieve logs from the terminated container:

```bash
kubectl logs <pod-name> --previous
```

This is especially useful when the container exits immediately after startup.

### Common causes of CrashLoopBackOff

* The application inside the container exits with a non-zero exit code
* The container command or arguments are misconfigured
* A liveness probe repeatedly fails, causing the kubelet to restart the container
