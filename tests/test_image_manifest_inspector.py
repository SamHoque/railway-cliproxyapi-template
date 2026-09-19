#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSPECTOR = ROOT / "scripts" / "inspect_image_manifest.sh"
IMAGE = "docker.io/eceasy/cli-proxy-api:v7.3.4"


class ImageManifestInspectorTests(unittest.TestCase):
    def run_inspector(self, mode: str):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "case \"$FAKE_INSPECT_MODE\" in\n"
                "  ready) printf '%s' '{\"schemaVersion\":2}' ;;\n"
                f"  missing) printf '%s\\n' 'ERROR: {IMAGE}: not found' >&2; exit 1 ;;\n"
                "  unexpected) printf '%s\\n' 'ERROR: registry authentication failed' >&2; exit 23 ;;\n"
                "  empty) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
            output = root / "manifest.json"
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["FAKE_INSPECT_MODE"] = mode
            result = subprocess.run(
                ["sh", str(INSPECTOR), IMAGE, str(output)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            return result, output.read_text(encoding="utf-8")

    def test_ready_manifest_is_retained(self) -> None:
        result, manifest = self.run_inspector("ready")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ready\n")
        self.assertEqual(manifest, '{"schemaVersion":2}')

    def test_exact_not_found_is_a_visible_defer(self) -> None:
        result, manifest = self.run_inspector("missing")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "defer:image-not-ready\n")
        self.assertEqual(manifest, "")
        self.assertIn(f"ERROR: {IMAGE}: not found", result.stderr)

    def test_unexpected_inspect_error_still_fails(self) -> None:
        result, _ = self.run_inspector("unexpected")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout, "")
        self.assertIn("registry authentication failed", result.stderr)

    def test_empty_success_still_fails(self) -> None:
        result, _ = self.run_inspector("empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("empty manifest", result.stderr)
