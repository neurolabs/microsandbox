"""Unit tests for `MountConfig` stat-virt + host-perms policy plumbing.

These tests exercise only the Python dataclass layer; no native binary
required.
"""

from __future__ import annotations

import pytest

from microsandbox import (
    DeploymentProfile,
    DiskImageFormat,
    HostPermissions,
    MountConfig,
    MountKind,
    NamedVolumeMode,
    SecurityProfile,
    StatVirtualization,
    Volume,
)


def test_bind_default_omits_policies() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data")
    d = mc._to_dict()
    assert "stat_virtualization" not in d
    assert "host_permissions" not in d
    assert d["bind"] == "/host/data"


def test_bind_rejects_policy_strings() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        readonly=True,
        stat_virtualization="relaxed",
        host_permissions="mirror",
    )
    with pytest.raises(TypeError, match=r"MountConfig\.stat_virtualization"):
        mc._to_dict()


def test_bind_serializes_security_mount_flags() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        nosuid=True,
        nodev=True,
    )
    d = mc._to_dict()
    assert d["nosuid"] is True
    assert d["nodev"] is True


def test_bind_with_relaxed_and_mirror_serializes_lowercase() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        stat_virtualization=StatVirtualization.RELAXED,
        host_permissions=HostPermissions.MIRROR,
    )
    d = mc._to_dict()
    assert d["stat_virtualization"] == "relaxed"
    assert d["host_permissions"] == "mirror"


def test_named_with_off_serializes() -> None:
    mc = MountConfig(
        kind=MountKind.NAMED,
        named="my-vol",
        stat_virtualization=StatVirtualization.OFF,
    )
    d = mc._to_dict()
    assert d["named"] == "my-vol"
    assert d["stat_virtualization"] == "off"
    assert "host_permissions" not in d


def test_tmpfs_rejects_stat_virt_at_serialization() -> None:
    mc = MountConfig(
        kind=MountKind.TMPFS,
        size_mib=64,
        stat_virtualization=StatVirtualization.RELAXED,
    )
    with pytest.raises(ValueError, match="only valid for BIND/NAMED"):
        mc._to_dict()


def test_tmpfs_rejects_host_perms_at_serialization() -> None:
    mc = MountConfig(
        kind=MountKind.TMPFS,
        host_permissions=HostPermissions.MIRROR,
    )
    with pytest.raises(ValueError, match="only valid for BIND/NAMED"):
        mc._to_dict()


def test_disk_rejects_stat_virt_at_serialization() -> None:
    mc = MountConfig(
        kind=MountKind.DISK,
        disk="/host/data.qcow2",
        format=DiskImageFormat.QCOW2,
        stat_virtualization=StatVirtualization.OFF,
    )
    with pytest.raises(ValueError, match="only valid for BIND/NAMED"):
        mc._to_dict()


def test_inactive_named_mode_is_validated_before_mount_dispatch() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        named_mode="existing",  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError, match=r"MountConfig\.named_mode"):
        mc._to_dict()


def test_named_mode_uses_canonical_enum_name() -> None:
    mc = MountConfig(
        kind=MountKind.NAMED,
        named="my-vol",
        named_mode=NamedVolumeMode.ENSURE_EXISTS,
    )

    assert mc._to_dict()["named_mode"] == "ensure-exists"


def test_stat_virtualization_str_values() -> None:
    assert StatVirtualization.STRICT.value == "strict"
    assert StatVirtualization.RELAXED.value == "relaxed"
    assert StatVirtualization.OFF.value == "off"


def test_host_permissions_str_values() -> None:
    assert HostPermissions.PRIVATE.value == "private"
    assert HostPermissions.MIRROR.value == "mirror"


def test_security_profile_str_values() -> None:
    assert SecurityProfile.DEFAULT.value == "default"
    assert SecurityProfile.RESTRICTED.value == "restricted"


def test_deployment_profile_str_values() -> None:
    assert DeploymentProfile.SINGLE_TENANT.value == "single-tenant"
    assert DeploymentProfile.MULTI_TENANT.value == "multi-tenant"


def test_bind_serializes_deny() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        deny=[".env", "sub/secret"],
    )
    d = mc._to_dict()
    assert d["deny"] == [".env", "sub/secret"]


def test_bind_omits_deny_when_empty_or_none() -> None:
    assert "deny" not in MountConfig(kind=MountKind.BIND, bind="/host/data")._to_dict()
    assert "deny" not in MountConfig(kind=MountKind.BIND, bind="/host/data", deny=[])._to_dict()


def test_non_bind_rejects_deny() -> None:
    for kind, kw in (
        (MountKind.NAMED, {"named": "vol"}),
        (MountKind.TMPFS, {"size_mib": 64}),
        (MountKind.DISK, {"disk": "/host/d.qcow2"}),
    ):
        mc = MountConfig(kind=kind, deny=[".env"], **kw)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="deny is only valid for BIND"):
            mc._to_dict()


def test_volume_bind_accepts_deny() -> None:
    mc = Volume.bind("/host/data", deny=[".env", "secret"])
    d = mc._to_dict()
    assert d["bind"] == "/host/data"
    assert d["deny"] == [".env", "secret"]


def test_volume_bind_omits_deny_when_unset() -> None:
    d = Volume.bind("/host/data")._to_dict()
    assert "deny" not in d


def test_apply_mount_contract_carries_deny() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", deny=[".env"])
    d = mc._to_dict()
    # apply_mount reads "deny" from this dict; the value must round-trip.
    assert d["bind"] == "/host/data"
    assert d["deny"] == [".env"]
