import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pendulum
import pytest

azm = pytest.importorskip("azul_bedrock.models_network", exc_type=ImportError)
dispatcher = pytest.importorskip("azul_bedrock.dispatcher", exc_type=ImportError)
azul_runner = pytest.importorskip("azul_runner", exc_type=ImportError)
azr_settings = azul_runner.settings

from azul_plugin_opencti_feed.main import AzulPluginOpenCTIFeed
from azul_plugin_opencti_feed.opencti import OpenCTIIndicator


TIME_NOW = pendulum.datetime(2026, 5, 21, 7, 0, 0, tz=pendulum.UTC)


def _now(*args, **kwargs):
    return TIME_NOW


class PluginTests(unittest.TestCase):
    def create_plugin(self, **overrides):
        cfg = {
            "opencti_url": "https://opencti.example",
            "opencti_token": "test-token",
            "request_timeout": 5,
            "api_retry_count": 0,
            "page_size": 10,
            "state_directory": tempfile.mkdtemp(),
            **overrides,
        }
        return AzulPluginOpenCTIFeed(azr_settings.parse_config(AzulPluginOpenCTIFeed, cfg))

    def compare_model(self, model, expected):
        actual = json.loads(model.model_dump_json(exclude_defaults=True))
        assert actual == expected

    @mock.patch("pendulum.now", _now)
    def test_gen_indicator_event_maps_opencti_indicator_like_report_feeds(self):
        plugin = self.create_plugin()
        indicator = OpenCTIIndicator(
            id="indicator--1",
            name="Known malware",
            description="A sample indicator",
            pattern="[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
            sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sha1="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            md5="cccccccccccccccccccccccccccccccc",
            score=90,
            confidence=75,
            labels=["malware"],
            external_references=["report: https://example.test/report"],
            updated_at="2026-01-02T00:00:00.000Z",
        )

        event = plugin._gen_indicator_event(indicator)

        self.compare_model(
            event,
            {
                "model_version": azm.CURRENT_MODEL_VERSION,
                "kafka_key": "opencti-feed-placeholder",
                "action": "mapped",
                "timestamp": "2026-05-21T07:00:00+00:00",
                "author": {"category": "plugin", "name": "OpenCTIFeed-OpenCTI", "version": "2026.05.21"},
                "entity": {
                    "md5": "cccccccccccccccccccccccccccccccc",
                    "sha1": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "features": [
                        {"name": "cti_confidence", "type": "integer", "value": "75"},
                        {"name": "cti_description", "type": "string", "value": "A sample indicator"},
                        {
                            "name": "cti_external_reference",
                            "type": "string",
                            "value": "report: https://example.test/report",
                        },
                        {"name": "cti_indicator_id", "type": "string", "value": "indicator--1"},
                        {"name": "cti_indicator_name", "type": "string", "value": "Known malware"},
                        {
                            "name": "cti_indicator_pattern",
                            "type": "string",
                            "value": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
                        },
                        {"name": "cti_label", "type": "string", "value": "malware"},
                        {"name": "cti_score", "type": "integer", "value": "90"},
                    ],
                },
                "source": {
                    "name": "opencti",
                    "path": [
                        {
                            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "action": "mapped",
                            "timestamp": "2026-05-21T07:00:00+00:00",
                            "author": {"category": "plugin", "name": "OpenCTIFeed-OpenCTI", "version": "2026.05.21"},
                        }
                    ],
                    "timestamp": "2026-05-21T07:00:00+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "opencti_indicator_id": "indicator--1",
                        "opencti_url": "https://opencti.example",
                    },
                },
                "dequeued": (
                    "opencti-feed.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                    "OpenCTIFeed-OpenCTI.2026.05.21.2026-05-21T07:00:00Z"
                ),
            },
        )

    @mock.patch.object(dispatcher.DispatcherAPI, "submit_events")
    def test_run_once_reads_state_processes_indicators_and_updates_state(self, mock_submit_events):
        with tempfile.TemporaryDirectory() as state_dir:
            plugin = self.create_plugin(state_directory=state_dir)
            indicator_with_sha = OpenCTIIndicator(
                id="indicator--1",
                name="Known malware",
                pattern="[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
                sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                updated_at="2026-01-02T00:00:00.000Z",
            )
            indicator_without_sha = OpenCTIIndicator(
                id="indicator--2",
                name="MD5 only",
                pattern="[file:hashes.MD5 = 'cccccccccccccccccccccccccccccccc']",
                md5="cccccccccccccccccccccccccccccccc",
                updated_at="2026-01-03T00:00:00.000Z",
            )

            with mock.patch("azul_plugin_opencti_feed.main.OpenCTIClient") as client_cls:
                client_cls.return_value.__enter__.return_value.iter_indicators.return_value = [
                    indicator_with_sha,
                    indicator_without_sha,
                ]

                processed = plugin.run_once()

            assert processed == 1
            assert Path(state_dir, "OpenCTI").read_text(encoding="utf-8") == "2026-01-02T00:00:00.000Z"
            client_cls.return_value.__enter__.return_value.iter_indicators.assert_called_once_with(updated_after=None)
            assert mock_submit_events.call_count == 2
            assert mock_submit_events.call_args_list[0].args[1] == azm.ModelType.Plugin
            assert mock_submit_events.call_args_list[1].args[1] == azm.ModelType.Status
