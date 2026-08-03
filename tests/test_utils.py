from app.utils import is_ipv4_only_hostname, merge_custom_fields, normalize_ip_input, slugify


def test_slugify_removes_accents_and_symbols():
    assert slugify("GENÉRICO / Modelo X") == "generico-modelo-x"


def test_normalize_ip_input_adds_default_prefix():
    assert normalize_ip_input("10.0.0.24") == "10.0.0.24/32"


def test_normalize_ip_input_keeps_prefix():
    assert normalize_ip_input("10.0.0.24/24") == "10.0.0.24/24"


def test_is_ipv4_only_hostname():
    assert is_ipv4_only_hostname("10.0.0.24") is True
    assert is_ipv4_only_hostname("SW-CCO-GDS7830") is False


def test_merge_custom_fields_preserves_existing_values():
    merged = merge_custom_fields({"site_tag": "A", "zabbix_hostid": "old"}, "10917")
    assert merged == {"site_tag": "A", "zabbix_hostid": "10917"}

