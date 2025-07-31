# vpa-latency

Test VPA Responsiveness and Recommendations

## Build stress-ng Container Image

```console
$ cd stress-ng-image/
$ podman build -t stress-ng:latest .
$ podman tag localhost/stress-ng:latest quay.io/akrzos/stress-ng:latest
$ podman push quay.io/akrzos/stress-ng:latest
```
