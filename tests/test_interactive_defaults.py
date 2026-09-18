"""Mode interaktif: fitur yang hanya bisa dipakai lewat flag harus muncul
beserta nilai default-nya, dan nilai itu harus tetap lewat validasi CLI.
"""
import argparse

import pytest

import spade


def _answers(monkeypatch, *values):
    """Jawab prompt `input()` berurutan; kalau daftarnya habis, raise EOFError."""
    queue = list(values)

    def _fake_input(*_args, **_kwargs):
        if not queue:
            raise EOFError
        return queue.pop(0)

    monkeypatch.setattr("builtins.input", _fake_input)


def _option(attr):
    for option in spade.INTERACTIVE_OPTIONS:
        if option["attr"] == attr:
            return option
    raise AssertionError(f"opsi {attr!r} tidak ada di INTERACTIVE_OPTIONS")


def _default_args():
    return spade.build_parser().parse_args([])


# ══════════════════════════════════════════════════════════════════
# 1. Registry vs daftar flag CLI
# ══════════════════════════════════════════════════════════════════

# Dest yang memang bukan bagian dari menu pengaturan lanjutan:
# - target/quick/detailed/recon_only : sudah jadi prompt target & mode
# - no_color                          : harus di-set sejak awal (memengaruhi menu)
# - no_impersonate                    : tercakup opsi --impersonate (nilai '-')
# - i_have_authorization              : digantikan prompt konfirmasi interaktif
# - help                              : bukan opsi scan
MENU_EXCLUDED_DESTS = {
    "target", "quick", "detailed", "recon_only", "no_color",
    "no_impersonate", "i_have_authorization", "help",
}


def test_menu_covers_every_flag_only_option():
    """Setiap flag CLI yang tidak diprompt di mode interaktif wajib ada di menu."""
    dests = set(vars(_default_args()))
    covered = {option["attr"] for option in spade.INTERACTIVE_OPTIONS}
    missing = dests - covered - MENU_EXCLUDED_DESTS
    assert not missing, f"opsi flag-only belum muncul di mode interaktif: {sorted(missing)}"


def test_menu_attrs_are_real_cli_dests():
    """Registry tidak boleh menunjuk atribut yang bukan flag CLI."""
    dests = set(vars(_default_args()))
    stray = {option["attr"] for option in spade.INTERACTIVE_OPTIONS} - dests
    assert not stray, f"registry menunjuk dest yang tidak ada: {sorted(stray)}"


def test_menu_entries_have_flag_label_and_group():
    """Setiap entri harus bisa dicetak: ada nama flag, label, dan kelompok."""
    for option in spade.INTERACTIVE_OPTIONS:
        assert option["flag"].startswith("-"), option
        assert option["label"] and option["group"], option
        assert option["kind"] in ("int", "float", "bool", "text", "list", "profile"), option


def test_menu_shows_documented_default_values():
    """Nilai default yang tampil harus sama dengan default flag CLI-nya."""
    args = _default_args()
    expected = {
        "workers": str(spade.DEFAULT_WORKERS),
        "impersonate": spade.DEFAULT_IMPERSONATE,
        "delay": "0",
        "max_rps": "0",
        "jitter": "0",
        "backoff_max": f"{spade.DEFAULT_BACKOFF_MAX:g}",
        "proxy_cooldown": f"{spade.DEFAULT_PROXY_COOLDOWN:g}",
        "crawl_depth": "2",
        "crawl_max": "30",
        "no_recon": "aktif",
        "port_scan": "mati",
        "safe_mode": "mati",
        "skip_ssl": "mati",
        "no_redact": "aktif",
        "proxy": "(kosong)",
        "cookie": "(kosong)",
        "json": "(kosong)",
    }
    for attr, text in expected.items():
        assert spade._interactive_option_text(_option(attr), args) == text, attr


def test_menu_output_default_follows_target_host():
    """Laporan HTML default ditampilkan sebagai nama berkas nyata, bukan string kosong."""
    args = _default_args()
    option = _option("output")
    assert spade._interactive_option_text(option, args, "example.com") == "spade_example.com.html"
    assert spade._interactive_option_text(option, args, "") == "spade_<host>.html"


# ══════════════════════════════════════════════════════════════════
# 2. Penerapan nilai (unit)
# ══════════════════════════════════════════════════════════════════

def test_bool_option_with_invert_sets_negative_flag():
    """Opsi 'Recon' menampilkan keadaan fitur, tapi menulis ke --no-recon."""
    option = _option("no_recon")
    args = argparse.Namespace(no_recon=False)
    assert spade._apply_option_value(option, args, "mati") is True
    assert args.no_recon is True
    assert spade._interactive_option_text(option, args) == "mati"


def test_list_option_appends_and_clears():
    option = _option("cookie")
    args = argparse.Namespace(cookie=[])
    assert spade._apply_option_value(option, args, "a=1") is True
    assert args.cookie == ["a=1"]
    assert spade._apply_option_value(option, args, "a=1") is False
    assert spade._apply_option_value(option, args, "-") is True
    assert args.cookie == []


def test_text_option_clear_token_empties_value():
    option = _option("bearer")
    args = argparse.Namespace(bearer="rahasia")
    assert spade._apply_option_value(option, args, "-") is True
    assert args.bearer == ""


def test_number_option_enforces_minimum_and_maximum():
    option = _option("jitter")
    args = argparse.Namespace(jitter=0.0)
    for bad in ("150", "-1", "bukan angka"):
        try:
            spade._apply_option_value(option, args, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad!r} seharusnya ditolak")
    assert spade._apply_option_value(option, args, "20") is True
    assert args.jitter == 20.0


def test_profile_option_can_disable_impersonation():
    option = _option("impersonate")
    args = argparse.Namespace(impersonate=spade.DEFAULT_IMPERSONATE, no_impersonate=False)
    assert spade._apply_option_value(option, args, "-") is True
    assert args.no_impersonate is True and args.impersonate == ""


def test_unknown_menu_number_is_rejected():
    try:
        spade._parse_option_numbers("99")
    except ValueError as exc:
        assert "bukan nomor opsi yang valid" in str(exc)
    else:
        raise AssertionError("nomor 99 seharusnya ditolak")


def test_interactive_conflicts_reports_safe_mode_clash():
    args = argparse.Namespace(safe_mode=True, active_writes=True, timing_probes=False,
                              check_smuggling=False, proxy=[], proxy_file="",
                              port_scan=False, detailed=False, recon_only=False)
    problems = spade._interactive_conflicts(args)
    assert problems and "--safe-mode" in problems[0]


# ══════════════════════════════════════════════════════════════════
# 3. Alur interaktif end-to-end
# ══════════════════════════════════════════════════════════════════

def test_interactive_enter_starts_scan_with_defaults(monkeypatch, vuln_server, tmp_path, capsys):
    """target -> mode -> Enter: semua default dipakai dan scan tetap jalan."""
    html_out = tmp_path / "interaktif.html"
    _answers(monkeypatch, vuln_server.base_url, "1", "29", str(html_out), "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "Pengaturan lanjutan" in out
    assert "[4] Recon" in out
    for flag in ("--workers", "--delay", "--max-rps", "--proxy", "--safe-mode",
                 "--active-writes", "--cert", "--resume", "--sarif"):
        assert flag in out, flag
    assert "Workers: 10 request paralel" in out
    assert html_out.exists()


def test_cli_with_target_skips_advanced_menu(vuln_server, tmp_path, capsys):
    """Jalur non-interaktif tidak boleh terganggu menu baru."""
    html_out = tmp_path / "cli.html"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "-o", str(html_out)]) == 0
    assert "Pengaturan lanjutan" not in capsys.readouterr().out
    assert html_out.exists()


def test_interactive_can_change_workers(monkeypatch, vuln_server, tmp_path, capsys):
    html_out = tmp_path / "workers.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),      # laporan HTML
             "1", "1",                 # Workers -> 1 (sekuensial)
             "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "Workers -> 1" in out
    assert "Workers: 1 request paralel (sekuensial)" in out
    assert html_out.exists()


def test_interactive_can_change_delay_and_jitter(monkeypatch, vuln_server, tmp_path, capsys):
    html_out = tmp_path / "throttle.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "3", "0.01",              # Delay
             "5", "10",                # Jitter
             "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "Throttle: delay 0.01s, tanpa batas laju, jitter ±10%" in out
    assert "Pengaturan diubah:" in out


def test_interactive_rejects_out_of_range_value(monkeypatch, vuln_server, tmp_path, capsys):
    """Nilai di luar rentang ditolak dan ditanyakan ulang, bukan bikin exit 2."""
    html_out = tmp_path / "jitter.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "5", "150", "20",         # Jitter: 150 ditolak, lalu 20
             "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "nilai maksimum 100" in out
    assert html_out.exists()


def test_interactive_rejects_unknown_menu_number(monkeypatch, vuln_server, tmp_path, capsys):
    html_out = tmp_path / "nomor.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "99", "29", str(html_out),
             "")
    assert spade.main([]) == 0
    assert "bukan nomor opsi yang valid" in capsys.readouterr().out


def test_interactive_question_mark_reprints_menu(monkeypatch, vuln_server, tmp_path, capsys):
    html_out = tmp_path / "ulang.html"
    _answers(monkeypatch, vuln_server.base_url, "1", "?", "29", str(html_out), "")
    assert spade.main([]) == 0
    assert capsys.readouterr().out.count("Kecepatan & stealth") == 2


def test_interactive_can_disable_impersonation(monkeypatch, vuln_server, tmp_path, capsys):
    html_out = tmp_path / "bot.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "2", "-",
             "")
    assert spade.main([]) == 0
    assert "Bot   : tanpa impersonation" in capsys.readouterr().out


def test_interactive_rejects_unknown_impersonation_profile(monkeypatch, vuln_server,
                                                           tmp_path, capsys):
    html_out = tmp_path / "bot2.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "2", "netscape", "chrome",
             "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "profil 'netscape' tidak dikenal" in out
    assert "Bot   : chrome" in out


def test_interactive_cookie_enables_authenticated_scan(monkeypatch, vuln_server,
                                                       tmp_path, capsys):
    html_out = tmp_path / "auth.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "10", "session=abc123",
             "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "Auth  :" in out
    assert "abc123" not in out, "nilai cookie tidak boleh bocor ke terminal"


def test_interactive_reports_conflict_before_starting(monkeypatch, vuln_server,
                                                      tmp_path, capsys):
    """Kombinasi salah dilaporkan di menu, bukan langsung exit 2."""
    html_out = tmp_path / "konflik.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "18", "aktif",            # Port scan padahal mode quick
             "",                       # Enter -> konflik, bukan exit 2
             "18", "mati",
             "")
    assert spade.main([]) == 0
    out = capsys.readouterr().out
    assert "Port scan butuh mode detailed" in out
    assert html_out.exists()


def test_interactive_eof_at_advanced_prompt_exits_cleanly(monkeypatch, capsys):
    """EOF di menu pengaturan harus keluar dengan kode 2 tanpa traceback."""
    _answers(monkeypatch, "contoh.test", "2")
    assert spade.main([]) == 2
    captured = capsys.readouterr()
    assert "EOF" in captured.err
    assert "Traceback" not in captured.err


def test_interactive_value_still_goes_through_cli_validation(monkeypatch, vuln_server,
                                                             tmp_path):
    """Nilai dari menu tetap divalidasi jalur CLI yang sama, bukan cuma di menu."""
    html_out = tmp_path / "key.html"
    _answers(monkeypatch, vuln_server.base_url, "1",
             "29", str(html_out),
             "26", str(tmp_path / "klien.key"),   # Client key tanpa client cert
             "")
    with pytest.raises(SystemExit) as excinfo:
        spade.main([])
    assert excinfo.value.code == 2
