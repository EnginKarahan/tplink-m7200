from tplink_m7200.status import parse_status

REAL = {
    "battery": {"connected": True, "charging": False, "voltage": 24},
    "wan": {"connectStatus": 4, "networkType": 3, "roaming": 0, "signalStrength": 2,
            "operatorName": "E-Plus", "snr": 26},
    "message": {"unreadMessages": 5},
    "result": 0,
}


def test_parse_real_status():
    s = parse_status(REAL)
    assert s.battery_percent == 24
    assert s.charging is False
    assert s.battery_present is True
    assert s.signal_bars == 2
    assert s.network_type == "4G"
    assert s.operator == "E-Plus"
    assert s.connected is True
    assert s.unread_sms == 5
    assert s.roaming is False


def test_network_type_mapping():
    expected = {0: "none", 1: "2G", 2: "3G", 3: "4G", 4: "3G", 5: "2G", 6: "3G", 99: "none"}
    for code, label in expected.items():
        assert parse_status({"wan": {"networkType": code}}).network_type == label


def test_missing_blocks_do_not_raise():
    s = parse_status({})
    assert s.battery_percent is None
    assert s.charging is None
    assert s.battery_present is False
    assert s.signal_bars is None
    assert s.network_type == "none"
    assert s.operator is None
    assert s.connected is False
    assert s.unread_sms == 0


def test_connect_status_as_string_and_clamping():
    s = parse_status({"wan": {"connectStatus": "4", "signalStrength": 9},
                      "battery": {"connected": 1, "voltage": 140, "charging": 1}})
    assert s.connected is True
    assert s.signal_bars == 4
    assert s.battery_percent == 100
    assert s.charging is True
