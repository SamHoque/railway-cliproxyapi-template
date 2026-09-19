#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StaticContractTests(unittest.TestCase):
    def test_runtime_source_hashes_match_manifest(self) -> None:
        records = {}
        for line in (ROOT / "SOURCE_SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(name, records)
            records[name] = digest
        expected = {
            "Dockerfile",
            "entrypoint.sh",
            "config-reconciler.go",
            "health-proxy.go",
            "health-proxy_test.go",
        }
        self.assertEqual(set(records), expected)
        for name, digest in records.items():
            actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, name)

    def test_dockerfile_matches_state_and_pinned_panel(self) -> None:
        state = json.loads((ROOT / "release-state.json").read_text())
        dockerfile = (ROOT / "Dockerfile").read_text()
        pin = f"eceasy/cli-proxy-api@{state['current']['digest']}"
        self.assertEqual(dockerfile.count(pin), 2)
        self.assertIn(
            "sha256:e2643e0875e0024e5ff9ddf4569e4c58611ab0456aeb6fa6065ed3e6c2b721f4",
            dockerfile,
        )
        self.assertIn(
            "releases/download/v1.22.6/management.html", dockerfile
        )
        self.assertNotIn(":latest", dockerfile)
        self.assertIn("-X main.embeddedVersion=${EMBEDDED_VERSION}", dockerfile)
        self.assertIn(
            "golang:1.25.5-bookworm@sha256:"
            "d9132cce84391efab786495288756d60e1da215b1f94e87860aeefc3d4c45b6d",
            dockerfile,
        )

    def test_railway_contract(self) -> None:
        config = json.loads((ROOT / "railway.json").read_text())
        self.assertEqual(config["build"]["builder"], "DOCKERFILE")
        deploy = config["deploy"]
        self.assertEqual(deploy["healthcheckPath"], "/healthz")
        self.assertEqual(deploy["numReplicas"], 1)
        self.assertEqual(deploy["restartPolicyType"], "ON_FAILURE")
        self.assertEqual(deploy["restartPolicyMaxRetries"], 10)
        self.assertFalse(deploy["sleepApplication"])

    def test_docs_have_no_forbidden_product_claim(self) -> None:
        text = "\n".join(
            path.read_text(errors="replace")
            for path in ROOT.rglob("*.md")
        )
        self.assertNotRegex(text.lower(), r"\bno api key needed\b")
        self.assertNotRegex(text.lower(), r"\bfully automatic railway updates\b")

    def test_no_secret_literals(self) -> None:
        suspicious = re.compile(
            r"(?i)(ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
            r"railway[_-]?(?:api[_-]?)?token\s*[:=]\s*['\"][^$<])"
        )
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            self.assertIsNone(
                suspicious.search(path.read_text(errors="replace")), str(path)
            )

    def test_workflow_keeps_unattended_cadence_and_gates_changes_on_success(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "release-controller.yml"
        ).read_text()
        self.assertEqual(workflow.count('cron: "17 */6 * * *"'), 1)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("default: check", workflow)
        self.assertEqual(
            workflow.count(
                "actions/checkout@"
                "3d3c42e5aac5ba805825da76410c181273ba90b1"
            ),
            1,
        )
        self.assertNotIn(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            workflow,
        )
        self.assertIn(
            "OPERATION: ${{ github.event.inputs.operation || 'check' }}",
            workflow,
        )
        self.assertIn(
            'echo "release-controller decision=${decision} '
            'candidate=${tag} digest=${digest}"',
            workflow,
        )
        self.assertIn('} >> "$GITHUB_STEP_SUMMARY"', workflow)
        self.assertIn("defer:*|noop:*)", workflow)
        self.assertIn("reject:*)", workflow)
        self.assertIn(
            "Release controller rejected candidate", workflow
        )
        self.assertIn(
            "Release controller returned an unknown decision", workflow
        )
        self.assertIn("smoke_mode=rollback-target", workflow)
        self.assertIn(
            'tests/run.sh "${{ steps.prepare.outputs.smoke_mode }}"', workflow
        )
        self.assertIn(
            'inspect_decision=$(sh scripts/inspect_image_manifest.sh', workflow
        )
        self.assertIn('defer:image-not-ready', workflow)
        self.assertIn('[[ "$inspect_decision" == "ready" ]]', workflow)
        self.assertIn(
            "if: success() && steps.prepare.outputs.changed == 'true'", workflow
        )
        self.assertIn(
            "git add Dockerfile release-state.json SOURCE_SHA256SUMS", workflow
        )

    def test_source_checksum_matches_current_dockerfile(self) -> None:
        controller_path = ROOT / "scripts" / "release_controller.py"
        self.assertTrue(controller_path.is_file())
        source = (ROOT / "SOURCE_SHA256SUMS").read_text()
        match = re.search(r"^([0-9a-f]{64})  Dockerfile$", source, re.MULTILINE)
        self.assertIsNotNone(match)
        assert match
        self.assertEqual(
            match.group(1), hashlib.sha256((ROOT / "Dockerfile").read_bytes()).hexdigest()
        )

    def test_persistent_config_is_atomic_and_fail_closed(self) -> None:
        entrypoint = (ROOT / "entrypoint.sh").read_text()
        reconciler = (ROOT / "config-reconciler.go").read_text()
        self.assertIn('CONFIG_FILE="${STATE_DIR}/config.yaml"', entrypoint)
        self.assertNotIn('CONFIG_FILE="${RUN_DIR}/config.yaml"', entrypoint)
        for required in (
            "syscall.O_NOFOLLOW",
            "syscall.O_EXCL",
            "syscall.Renameat",
            "syscall.Fsync",
            "info.Nlink == 1",
            "info.Mode&0777 == 0600",
            "security field order drift",
            "unknown config field",
            "api key cardinality drift",
            '"host: \\"127.0.0.1\\"',
            '"ws-auth: true',
            "extractSupportedDiscovery",
            "defaultDiscoveryConfig",
            "too many discovery subtypes",
        ):
            self.assertIn(required, reconciler)
        self.assertNotIn("stripSupportedDiscovery", reconciler)
        health_proxy = (ROOT / "health-proxy.go").read_text()
        self.assertIn('"/data/state/config.yaml"', health_proxy)
        self.assertNotIn('"/run/cliproxy/config.yaml"', health_proxy)

    def test_runtime_updater_is_private_bounded_and_rootless(self) -> None:
        source = (ROOT / "health-proxy.go").read_text()
        entrypoint = (ROOT / "entrypoint.sh").read_text()
        run_script = (ROOT / "tests" / "run.sh").read_text()
        runtime_fixture = (
            ROOT / "tests" / "test_runtime_updates.sh"
        ).read_text()
        for required in (
            "defaultInterval    = 6 * time.Hour",
            "maxJitter          = 30 * time.Minute",
            "maxAttemptGap      = 23 * time.Hour",
            "releaseSoak        = 6 * time.Hour",
            "checksums.txt",
            "same-tag checksum drift",
            "archive entry contract rejected",
            "links and non-regular entries rejected",
            "binary-only rollback",
            "syscall.O_NOFOLLOW",
            "syscall.Flock",
            '"127.0.0.1:8317"',
        ):
            self.assertIn(required, source)
        self.assertNotRegex(source, r'HandleFunc\("/(?:update|admin|status)')
        self.assertIn('"$DATA_DIR/update"', entrypoint)
        self.assertIn("--no-new-privs", entrypoint)
        self.assertIn('--reuid="$APP_UID"', entrypoint)
        self.assertIn("tests/test_runtime_updates.sh", run_script)
        self.assertIn("-e CGO_ENABLED=0", runtime_fixture)
        self.assertIn("ROOT=$(CDPATH='' cd --", runtime_fixture)
        self.assertIn(
            'cleanup\nmkdir -m 0700 "$FIXTURE_ROOT"',
            runtime_fixture,
        )
        self.assertNotIn('"$FIXTURE_ROOT:/out"', runtime_fixture)
        self.assertNotIn("--user", runtime_fixture)
        self.assertNotIn("GOCACHE", runtime_fixture)
        self.assertIn(
            "-o /tmp/cli-proxy-api", runtime_fixture
        )
        self.assertIn(
            "cat /tmp/cli-proxy-api' > "
            '"$FIXTURE_ROOT/cli-proxy-api"',
            runtime_fixture,
        )
        self.assertIn(
            "# shellcheck disable=SC2016  "
            "# Deliberate literal linker-value injection probe.\n"
            "INJECTION_TAG="
            "'v0.0.0$(touch>/tmp/fixture-injection)'",
            runtime_fixture,
        )
        self.assertIn(
            'grep -aF "$INJECTION_TAG" '
            '"$FIXTURE_ROOT/cli-proxy-api"',
            runtime_fixture,
        )
        self.assertIn(
            'chmod 0755 "$FIXTURE_ROOT/cli-proxy-api"',
            runtime_fixture,
        )
        self.assertIn(
            'tar -tzf "$FIXTURE_ROOT/candidate.tar.gz"',
            runtime_fixture,
        )
        self.assertIn(
            "EMBEDDED_TAG=$(sed -n "
            "'s/^ARG EMBEDDED_VERSION=//p' "
            '"$ROOT/Dockerfile")',
            runtime_fixture,
        )
        self.assertIn("PROMOTED_TAG=$(fixture_tag 1)", runtime_fixture)
        self.assertIn('build_candidate "$PROMOTED_TAG"', runtime_fixture)
        self.assertIn('wait_tag "$PROMOTED_TAG"', runtime_fixture)
        self.assertIsNone(
            re.search(
                r"(?m)^(?:build_candidate|wait_tag)\s+"
                r"v\d+\.\d+\.\d+\s*$",
                runtime_fixture,
            )
        )
        self.assertNotIn("\n! docker", runtime_fixture)


if __name__ == "__main__":
    unittest.main()
