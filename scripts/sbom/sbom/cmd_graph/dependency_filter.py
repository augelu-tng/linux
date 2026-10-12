# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

import re

from sbom.path_utils import PathStr

# Regex patterns for dependencies that should not be tracked in the
# dependency graph. Paths are relative to the object tree or source tree.
_EXCLUDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Directories normally containing host-tools and scripts
    re.compile(r"^scripts/"),
    re.compile(r"^tools/"),
    re.compile(r"^arch/[^/]+/tools/"),
    # Host helper scripts
    re.compile(r".*\.sh$"),
    re.compile(r".*\.py$"),
    re.compile(r".*\.pl$"),
    re.compile(r".*\.awk$"),
    # Other
    re.compile(r".*\.xsd$"),
    re.compile(r".*purgatory\.chk$"),
    re.compile(r".*\.genkey$"),
    re.compile(r".*\.md$"),
    re.compile(r"^include/config/"),
)

# Exact paths for dependencies that should not be tracked in the dependency graph.
_EXCLUDE_PATHS: frozenset[str] = frozenset(
    {
        # Host-tool executables
        "certs/extract-cert",
        "security/selinux/genheaders",
        "usr/gen_init_cpio",
        "drivers/gpu/drm/radeon/mkregtable",
        "drivers/video/logo/pnmtologo",
        "lib/raid/raid6/mktables",
        "fs/smb/client/gen_smb1_mapping",
        "fs/smb/client/gen_smb2_mapping",
        # x86
        "arch/x86/boot/compressed/mkpiggy",
        "arch/x86/boot/mkcpustr",
        # arm
        "arch/arm/vdso/vdsomunge",
        # arm64
        "arch/arm64/kvm/hyp/nvhe/gen-hyprel",
        "arch/arm64/kernel/pi/relacheck",
    }
)

# Exceptions to the exclusion lists above. These files are genuine
# kernel inputs despite living in directories normally used for host tools and helpers.
_INCLUDE_PATHS: frozenset[str] = frozenset(
    {
        # kernel inputs under scripts and tools directories.
        "scripts/module-common.c",
        "scripts/module.lds",
        "scripts/module.lds.S",
        "scripts/syscall.tbl",
        "tools/lib/bpf/btf_iter.c",
        "tools/lib/bpf/btf_relocate.c",
        "tools/lib/bpf/relo_core.c",
        "tools/lib/bpf/relo_core.h",
        # Architecture data inputs
        "arch/arm/tools/mach-types",
        "arch/arm/tools/syscall.tbl",
        "arch/arm64/tools/cpucaps",
        "arch/arm64/tools/sysreg",
        "arch/arm64/tools/syscall_32.tbl",
        "arch/arm64/tools/syscall_64.tbl",
        "arch/sh/tools/mach-types",
        # non host-tool Perlasm sources
        "lib/crypto/mips/poly1305-mips.pl",
        "lib/crypto/powerpc/aesp8-ppc.pl",
        "lib/crypto/powerpc/ghashp8-ppc.pl",
        "lib/crypto/riscv/poly1305-riscv.pl",
        "arch/powerpc/crypto/aesp10-ppc.pl",
        "arch/powerpc/crypto/ghashp10-ppc.pl",
    }
)


def should_include_dependency(path: PathStr, obj_tree: PathStr, src_tree: PathStr) -> bool:
    """
    Return whether a `.cmd` dependency should appear in the tracked dependency graph.

    Track files that are inputs to compiling or linking artifacts that end up in the
    kernel image or loadable modules (e.g. source → object → archive → image/module).
    Exclude host tools and helper scripts whose code is not linked into the kernel.

    Args:
        path: absolute path to the dependency.
        obj_tree: absolute path to the object tree.
        src_tree: absolute path to the source tree.

    Returns:
        True if the dependency should be included in the dependency graph.
    """
    if path.startswith(obj_tree + "/") or not path.startswith(src_tree + "/"):
        filter_path = path.removeprefix(obj_tree + "/")
    else:
        filter_path = path.removeprefix(src_tree + "/")
    if filter_path in _INCLUDE_PATHS:
        return True

    if filter_path in _EXCLUDE_PATHS:
        return False

    return not any(pattern.match(filter_path) for pattern in _EXCLUDE_PATTERNS)
