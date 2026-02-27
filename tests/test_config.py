from airsnitch.config import OUI_VENDORS, VULNERABLE_DEVICES


def test_vulnerable_devices_structure():
    for vendor, models in VULNERABLE_DEVICES.items():
        assert isinstance(vendor, str)
        for model, attacks in models.items():
            assert isinstance(model, str)
            assert isinstance(attacks, list)
            for attack in attacks:
                assert attack in ("gtk_injection", "gateway_bounce", "downlink_spoof", "uplink_impersonation")


def test_oui_vendors_format():
    for prefix, vendor in OUI_VENDORS.items():
        # OUI prefix format: XX:XX:XX
        assert len(prefix) == 8
        assert prefix[2] == ":" and prefix[5] == ":"
        assert vendor in VULNERABLE_DEVICES
