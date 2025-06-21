# Copyright 2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit linux-mod-r1 systemd

DESCRIPTION="Security Hardening Linux Security Module"
HOMEPAGE="https://github.com/linux-hardening/hardening-lsm"
SRC_URI="${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="tools doc"

DEPEND="
    virtual/linux-sources
    sys-kernel/linux-headers
"
RDEPEND="${DEPEND}
    tools? ( dev-lang/python:3 )
"

MODULE_NAMES="hardening(security:${S})"
BUILD_TARGETS="modules"

src_compile() {
    linux-mod-r1_src_compile
}

src_install() {
    linux-mod-r1_src_install
    
    if use tools; then
        dobin tools/hardening-ctl
        dobin tools/hardening-status
        dobin tools/hardening-profiles
        systemd_dounit packaging/systemd/hardening-lsm.service
    fi
    
    if use doc; then
        dodoc README.md
        docinto examples
        dodoc -r examples/*
    fi
    
    # Install default config
    insinto /etc/hardening-lsm
    doins config/default.conf
    
    # Install profile examples
    insinto /etc/hardening-lsm/profiles
    doins profiles/*.profile
}

pkg_postinst() {
    linux-mod-r1_pkg_postinst
    
    elog "Security Hardening LSM has been installed."
    elog ""
    elog "To activate the module, add the following to your kernel command line:"
    elog "    lsm=landlock,lockdown,yama,loadpin,safesetid,hardening,selinux,apparmor"
    elog ""
    elog "You can add this to /etc/default/grub:"
    elog "    GRUB_CMDLINE_LINUX_DEFAULT=\"... lsm=...,hardening,...\""
    elog ""
    elog "Then run: grub-mkconfig -o /boot/grub/grub.cfg"
    elog ""
    if use tools; then
        elog "Management tools installed:"
        elog "    hardening-ctl     - Control the module"
        elog "    hardening-status  - View status"
        elog "    hardening-profiles - Manage profiles"
    fi
}