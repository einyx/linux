Format: 1.0
Source: hardening-lsm
Binary: hardening-lsm-dkms, hardening-lsm-tools, hardening-lsm-doc
Architecture: any all
Version: 1.0.0-1
Maintainer: Alessio <alessio@linux.com>
Homepage: https://github.com/linux-hardening/hardening-lsm
Standards-Version: 4.6.0
Build-Depends: debhelper (>= 13), dkms, linux-headers-generic, build-essential, libssl-dev
Package-List:
 hardening-lsm-dkms deb kernel optional arch=all
 hardening-lsm-doc deb doc optional arch=all
 hardening-lsm-tools deb kernel optional arch=any
Checksums-Sha1:
 fac1464c1efd06f8d16ca89abaa1af872c9c5d8f 40655 hardening-lsm_1.0.0.orig.tar.gz
 d508f81a2a59ac8623e6785d7d55b914ac20b408 338 hardening-lsm_1.0.0-1.diff.gz
Checksums-Sha256:
 14fd3c56101068b61fb9d5d1a39be114642924636d687a8ccd4e0033ec4f9c74 40655 hardening-lsm_1.0.0.orig.tar.gz
 220c2027886c0896033d99b92d88ee5304e02b1020c5e09fbac30f6d7d38c1ed 338 hardening-lsm_1.0.0-1.diff.gz
Files:
 309ae08d45e43e462b4eac687996fe69 40655 hardening-lsm_1.0.0.orig.tar.gz
 02f237707480e505e187c67273ceafc6 338 hardening-lsm_1.0.0-1.diff.gz
