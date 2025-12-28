---
title: Configure Liveness and Readiness Probes
source: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
section: Liveness and Readiness Probes
doc_type: kubernetes_official
intended_use: rag
---

## Liveness and Readiness Probes

Kubernetes uses probes to determine the health of containers.

### Liveness probe

A liveness probe checks whether a container is still running properly.

If a liveness probe fails, the kubelet kills the container and restarts it.

Repeated liveness probe failures can lead to a `CrashLoopBackOff` state even if the application itself does not crash.

Example liveness probe configuration:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
````

If the application takes longer to start than expected, the probe may fail repeatedly.

### Readiness probe

A readiness probe indicates whether a container is ready to receive traffic.

If the readiness probe fails:

* The container is removed from Service endpoints
* The container is **not restarted**

Readiness probe failures do not cause CrashLoopBackOff but may appear related during debugging.

### Diagnosing probe failures

Probe failures appear in Pod events:

```text
Warning  Unhealthy  kubelet  Liveness probe failed
```

Use `kubectl describe pod` to inspect these events.
