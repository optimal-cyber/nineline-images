# NINELINE ubi9-hardened: Red Hat compatible minimal base built only from UBI 9 content.
# Installs glibc, coreutils-single and CA certificates into an empty root, strips
# setuid/setgid bits and package caches, and runs as non-root (uid 65532).
# Built for linux/amd64 and linux/arm64 by .github/workflows/factory.yml.
#
# ca-certificates requires bash (its install scripts), so dnf pulls a shell into
# the root. The shell is only needed at install time; it is removed from the
# files and from the RPM database with `rpm -e --nodeps bash` so that the image
# ships without one and the package list scanners read is accurate.
FROM registry.access.redhat.com/ubi9/ubi:latest AS build
RUN set -e; \
    dnf -y update; \
    mkdir -p /mnt/rootfs; \
    dnf install -y --installroot /mnt/rootfs --releasever 9 \
        --setopt=reposdir=/etc/yum.repos.d --disablerepo='*' --enablerepo='ubi-9-*' \
        --setopt=install_weak_deps=False --nodocs \
        glibc-minimal-langpack coreutils-single ca-certificates; \
    dnf --installroot /mnt/rootfs clean all; \
    rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/dnf* /mnt/rootfs/var/lib/dnf; \
    rpm --root /mnt/rootfs -e --nodeps bash; \
    find /mnt/rootfs -xdev -type f -perm /6000 -exec chmod a-s {} +; \
    echo "nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin" >> /mnt/rootfs/etc/passwd; \
    echo "nonroot:x:65532:" >> /mnt/rootfs/etc/group; \
    mkdir -p /mnt/rootfs/home/nonroot; \
    chown 65532:65532 /mnt/rootfs/home/nonroot

FROM scratch
COPY --from=build /mnt/rootfs/ /
LABEL org.opencontainers.image.title="NINELINE ubi9-hardened" \
      org.opencontainers.image.description="Red Hat compatible minimal base from UBI 9 content: no package manager, setuid bits removed, non-root." \
      org.opencontainers.image.vendor="Optimal, LLC" \
      org.opencontainers.image.source="https://github.com/optimal-cyber/nineline-images" \
      org.opencontainers.image.url="https://9line.gooptimal.io"
USER 65532:65532
WORKDIR /home/nonroot
