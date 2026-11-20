# Fork-only trial. It adds the kernel arguments of the MNT Reform 2 (i.MX8MQ)
# to a published arm64 image. The image writes generic arguments, and this
# board needs its serial console, a larger CMA and two PCIe settings.
# Remove this directory before the change goes upstream.
ARG FROM_IMAGE=scratch
FROM ${FROM_IMAGE}
RUN grep -q '^    set baseExtraArgs=""$' /etc/cos/bootargs.cfg && \
    sed -i 's|^    set baseExtraArgs=""$|    set baseExtraArgs="console=ttymxc0,115200 console=tty1 cma=512M pci=nomsi pcie_aspm=off"|' /etc/cos/bootargs.cfg && \
    grep -n 'baseExtraArgs=' /etc/cos/bootargs.cfg
