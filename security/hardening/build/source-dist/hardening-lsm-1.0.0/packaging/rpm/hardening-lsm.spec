Name:           hardening-lsm
Version:        1.0.0
Release:        1%{?dist}
Summary:        Security Hardening Linux Security Module

License:        GPL-2.0-only
URL:            https://github.com/linux-hardening/hardening-lsm
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  kernel-devel
BuildRequires:  dkms
BuildRequires:  gcc
BuildRequires:  make
Requires:       dkms
Requires:       kernel-headers

%description
A comprehensive Linux Security Module providing innovative security features:
- ML-inspired behavioral anomaly detection
- Temporal access control (time-based policies)
- Process lineage tracking
- Container-aware security policies
- Network behavior profiling
- Memory access pattern analysis
- Entropy-based randomization
- Adaptive security levels

%package tools
Summary:        Management tools for Security Hardening LSM
Requires:       python3

%description tools
Command-line tools and utilities for managing the Security Hardening LSM.

%package doc
Summary:        Documentation for Security Hardening LSM
BuildArch:      noarch

%description doc
Documentation and examples for the Security Hardening Linux Security Module.

%prep
%autosetup

%build
# Module will be built by DKMS

%install
# Install DKMS source
mkdir -p %{buildroot}/usr/src/%{name}-%{version}
cp -r * %{buildroot}/usr/src/%{name}-%{version}/

# Install DKMS config
install -D -m 644 packaging/dkms/dkms.conf %{buildroot}/usr/src/%{name}-%{version}/dkms.conf

# Install tools
mkdir -p %{buildroot}%{_bindir}
install -m 755 tools/hardening-ctl %{buildroot}%{_bindir}/
install -m 755 tools/hardening-status %{buildroot}%{_bindir}/
install -m 755 tools/hardening-profiles %{buildroot}%{_bindir}/

# Install documentation
mkdir -p %{buildroot}%{_docdir}/%{name}
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/
cp -r examples %{buildroot}%{_docdir}/%{name}/

# Install systemd service
mkdir -p %{buildroot}%{_unitdir}
install -m 644 packaging/systemd/hardening-lsm.service %{buildroot}%{_unitdir}/

%post
dkms add -m %{name} -v %{version} --rpm_safe_upgrade
dkms build -m %{name} -v %{version}
dkms install -m %{name} -v %{version}

# Update GRUB to include hardening in LSM list
if ! grep -q "hardening" /etc/default/grub; then
    sed -i 's/\(GRUB_CMDLINE_LINUX=".*\)"$/\1 lsm=landlock,lockdown,yama,loadpin,safesetid,hardening,selinux,apparmor"/' /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg
fi

%preun
if [ "$1" = "0" ]; then
    dkms remove -m %{name} -v %{version} --all --rpm_safe_upgrade
fi

%files
%license COPYING
%doc README.md
/usr/src/%{name}-%{version}

%files tools
%{_bindir}/hardening-ctl
%{_bindir}/hardening-status
%{_bindir}/hardening-profiles
%{_unitdir}/hardening-lsm.service

%files doc
%{_docdir}/%{name}

%changelog
* Fri Jun 21 2024 Alessio <alessio@linux.com> - 1.0.0-1
- Initial release
- ML-inspired behavioral anomaly detection
- Temporal access control
- Process lineage tracking
- Container-aware security
- Network behavior profiling
- Memory access pattern analysis