FROM registry.access.redhat.com/ubi9/ubi-minimal

ARG STRESS_NG_VERSION="V0.19.02"
ARG STRESS_NG_TARBALL="stress-ng-${STRESS_NG_VERSION}.tar.gz"
ARG STRESS_NG_URL="https://github.com/ColinIanKing/stress-ng/archive/refs/tags/${STRESS_NG_VERSION}.tar.gz"
ARG STRESS_NG_DIR="stress-ng-${STRESS_NG_VERSION#V}"

WORKDIR /tmp/build

RUN microdnf install -y tar gzip gcc make glibc-devel && \
    microdnf clean all

RUN curl -L "${STRESS_NG_URL}" -o "${STRESS_NG_TARBALL}"
RUN tar -xzf "${STRESS_NG_TARBALL}"
WORKDIR /tmp/build/${STRESS_NG_DIR}

RUN make
RUN make install

RUN rm -rf /tmp/build && \
    microdnf remove -y tar gzip gcc make && \
    microdnf clean all

WORKDIR /tmp

ENTRYPOINT ["/usr/local/bin/stress-ng"]

CMD ["--help"]
