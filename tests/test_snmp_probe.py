import pytest

from app import snmp_probe
from app import services


class _FakeSnmpPart:
    def __init__(self, value: str) -> None:
        self._value = value

    def prettyPrint(self) -> str:
        return self._value


class _FakeObjectType:
    def __init__(self, value: str) -> None:
        self._value = value

    def __getitem__(self, index: int):
        if index == 1:
            return _FakeSnmpPart(self._value)
        raise IndexError(index)

    def prettyPrint(self) -> str:
        return f"SNMPv2-MIB::sysName.0 = {self._value}"


@pytest.mark.anyio
async def test_fetch_scalar_values_parses_var_binds(monkeypatch):
    async def fake_get_cmd(*args, **kwargs):
        return (
            None,
            None,
            None,
            [
                (_FakeSnmpPart("1.3.6.1.2.1.1.1.0"), _FakeSnmpPart("Intelbras Platform Software")),
                (_FakeSnmpPart("1.3.6.1.2.1.1.5.0"), _FakeSnmpPart("SW-EDGE-01")),
            ],
        )

    monkeypatch.setattr(snmp_probe, "get_cmd", fake_get_cmd)

    values = await snmp_probe._fetch_scalar_values("10.0.0.19", "public", timeout=1.0, retries=0)

    assert values["sys_descr"] == "Intelbras Platform Software"
    assert values["sys_name"] == "SW-EDGE-01"


def test_normalize_snmp_mac_handles_hex_prefixes():
    assert snmp_probe._normalize_mac("0x58108c27ef28") == "58:10:8C:27:EF:28"
    assert services._normalize_snmp_mac("0x58108c27ef28") == "58:10:8C:27:EF:28"


def test_clean_value_handles_pysnmp_objecttype_format():
    assert snmp_probe._clean_value(_FakeObjectType("SW-BILHETERIA")) == "SW-BILHETERIA"
