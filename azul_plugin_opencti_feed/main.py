"""Read OpenCTI indicators and ingest them into Azul as binary events."""

from __future__ import annotations

import logging
import os
import traceback
from typing import Any, cast

import httpx
import pendulum
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from azul_runner import Feature, FeatureType, FeatureValue, Plugin, add_settings
from azul_runner import main as azr_main
from azul_runner import network_transform as azr_network_transform
from azul_runner import settings as azr_settings

from .opencti import OpenCTIClient, OpenCTIError, OpenCTIIndicator

logger = logging.getLogger(__name__)
DEFAULT_STATE_DIR = os.path.expanduser("~/.opencti-feed")
ftInt, ftStr = (FeatureType.Integer, FeatureType.String)


class AzulPluginOpenCTIFeed(Plugin):
    """Batch plugin that ingests OpenCTI file-hash indicators into Azul."""

    VERSION = "2026.05.21"
    SETTINGS = add_settings(
        opencti_url=(str, ""),
        opencti_token=(str, ""),
        opencti_publisher=(str, "OpenCTI"),
        request_timeout=(int, 30),
        api_retry_count=(int, 3),
        page_size=(int, 100),
        state_directory=(str, DEFAULT_STATE_DIR),
        feed_source_name=(str, "opencti"),
        feed_security=(str, "OFFICIAL"),
        namespace_suffix=(str, ""),
    )
    ENTITY_TYPE = ""
    FEATURES = [
        Feature("cti_indicator_id", desc="OpenCTI indicator ID ingested into Azul", type=ftStr),
        Feature("cti_indicator_name", desc="OpenCTI indicator name ingested into Azul", type=ftStr),
        Feature("cti_indicator_pattern", desc="OpenCTI indicator pattern ingested into Azul", type=ftStr),
        Feature("cti_description", desc="OpenCTI indicator description", type=ftStr),
        Feature("cti_score", desc="OpenCTI score value", type=ftInt),
        Feature("cti_confidence", desc="OpenCTI confidence value", type=ftInt),
        Feature("cti_label", desc="OpenCTI labels attached to the indicator", type=ftStr),
        Feature("cti_external_reference", desc="OpenCTI indicator external references", type=ftStr),
    ]

    def __init__(self, config: azr_settings.Settings | dict | None = None) -> None:
        super().__init__(config)
        cfg = cast(Any, self.cfg)
        if not cfg.opencti_url:
            raise RuntimeError("OpenCTI URL must be set")
        if not httpx.URL(cfg.opencti_url).is_absolute_url:
            raise RuntimeError(f"Unable to use OpenCTI with URL '{cfg.opencti_url}'")
        if not cfg.opencti_token:
            raise RuntimeError("OpenCTI API token must be set")
        for cfg_var in ("request_timeout", "api_retry_count", "page_size"):
            try:
                setattr(self.cfg, cfg_var, int(getattr(self.cfg, cfg_var)))
            except ValueError as e:
                raise ValueError(f"Config setting {cfg_var} must be an int value") from e

        self.author = azm.Author(name=self.NAME, version=self.VERSION, category="plugin")
        self.dp = dispatcher.DispatcherAPI(
            events_url=self.cfg.events_url,
            data_url=self.cfg.data_url,
            retry_count=self.cfg.request_retry_count,
            timeout=self.cfg.request_timeout,
            author_name=self.NAME,
            author_version=self.VERSION,
            deployment_key=self.cfg.deployment_key,
        )
        self.register_multiplugin(self.cfg.opencti_publisher, None, lambda j: None)
        self.publisher_author = azr_network_transform.gen_author(
            self, self.get_multiplugin(self.cfg.opencti_publisher)
        )

    def run_once(self) -> int:
        """Read OpenCTI once, submit mapped events to Azul, and update feed state."""
        os.makedirs(self.cfg.state_directory, exist_ok=True)
        registration = azr_network_transform.get_registrations(self)
        self.dp.submit_events(registration, azm.ModelType.Plugin)

        processed = 0
        last_state = self._load_state()
        newest_state = last_state
        try:
            with OpenCTIClient(
                base_url=cast(Any, self.cfg).opencti_url,
                token=cast(Any, self.cfg).opencti_token,
                timeout=cast(Any, self.cfg).request_timeout,
                retry_count=cast(Any, self.cfg).api_retry_count,
                page_size=cast(Any, self.cfg).page_size,
            ) as client:
                for indicator in client.iter_indicators(updated_after=last_state):
                    if not indicator.sha256:
                        logger.info("Skipping OpenCTI indicator %s because it has no SHA-256", indicator.id)
                        continue
                    self.process_indicator(indicator)
                    processed += 1
                    if indicator.updated_at:
                        newest_state = indicator.updated_at
                        self._save_state(newest_state)
        except (httpx.HTTPError, OpenCTIError):
            logger.error("Failed to ingest OpenCTI feed\n%s", traceback.format_exc())
            raise

        if newest_state and newest_state != last_state:
            self._save_state(newest_state)
        return processed

    def process_indicator(self, indicator: OpenCTIIndicator) -> azm.BinaryEvent:
        """Create and submit the Azul status event for a single OpenCTI indicator."""
        event = self._gen_indicator_event(indicator)
        event_duplicate = event.model_copy(deep=True)
        event_duplicate.entity.features = []
        event_duplicate.entity.datastreams = []
        event_duplicate.entity.info = {}

        status_event = azm.StatusEvent(
            model_version=azm.CURRENT_MODEL_VERSION,
            kafka_key=f"opencti-feed-{indicator.sha256}",
            timestamp=pendulum.now(pendulum.UTC),
            author=self.publisher_author,
            entity=azm.StatusEvent.Entity(
                input=event_duplicate,
                status=azm.StatusEnum.COMPLETED,
                runtime=0,
                results=[event],
            ),
        )
        self.dp.submit_events([status_event], azm.ModelType.Status)
        return event

    def _gen_indicator_event(self, indicator: OpenCTIIndicator) -> azm.BinaryEvent:
        if not indicator.sha256:
            raise ValueError("Attempting to create OpenCTI mapped event without a sha256.")

        timestamp = pendulum.now(pendulum.UTC).to_iso8601_string()
        features = self._indicator_features(indicator)
        entity = azm.BinaryEvent.Entity(
            sha256=indicator.sha256,
            sha1=indicator.sha1 or None,
            md5=indicator.md5 or None,
            features=self._convert_to_features(features),
        )
        references = {
            "opencti_indicator_id": indicator.id,
            "opencti_url": cast(Any, self.cfg).opencti_url,
        }
        return azm.BinaryEvent(
            kafka_key="opencti-feed-placeholder",
            dequeued=f"opencti-feed.{entity.sha256}.{self.publisher_author.name}.{self.publisher_author.version}.{timestamp}",
            action=azm.BinaryAction.Mapped,
            model_version=azm.CURRENT_MODEL_VERSION,
            timestamp=timestamp,
            author=self.publisher_author,
            entity=entity,
            source=azm.Source(
                name=self.cfg.feed_source_name,
                timestamp=timestamp,
                references=references,
                path=[
                    azm.PathNode(
                        author=self.publisher_author,
                        action=azm.BinaryAction.Mapped,
                        timestamp=timestamp,
                        sha256=entity.sha256,
                    )
                ],
                security=self.cfg.feed_security,
            ),
        )

    @staticmethod
    def _indicator_features(indicator: OpenCTIIndicator) -> dict[str, list[str | int]]:
        features: dict[str, list[str | int]] = {}
        if indicator.confidence is not None:
            features["cti_confidence"] = [indicator.confidence]
        if indicator.description:
            features["cti_description"] = [indicator.description]
        if indicator.external_references:
            features["cti_external_reference"] = indicator.external_references
        if indicator.id:
            features["cti_indicator_id"] = [indicator.id]
        if indicator.name:
            features["cti_indicator_name"] = [indicator.name]
        if indicator.pattern:
            features["cti_indicator_pattern"] = [indicator.pattern]
        if indicator.labels:
            features["cti_label"] = indicator.labels
        if indicator.score is not None:
            features["cti_score"] = [indicator.score]
        return features

    def _convert_to_features(self, features: dict[str, list[str | int]]):
        features_as_fv = {}
        for key, values in features.items():
            features_as_fv[key] = [FeatureValue(value) for value in values]
        return azr_network_transform._to_api_features(self, features_as_fv)

    def _state_path(self) -> str:
        return os.path.join(self.cfg.state_directory, self.cfg.opencti_publisher)

    def _load_state(self) -> str | None:
        state_path = self._state_path()
        if not os.path.exists(state_path):
            return None
        with open(state_path, encoding="utf-8") as state_file:
            value = state_file.read().strip()
        return value or None

    def _save_state(self, value: str) -> None:
        with open(self._state_path(), "w", encoding="utf-8") as state_file:
            state_file.write(value)


def main():
    """Plugin command-line entrypoint."""
    args = azr_main.parse_args()
    config: dict[str, Any] = {}
    if args.server:
        config["events_url"] = args.server
        config["data_url"] = args.server
    if args.config:
        config.update({name: value for name, value in args.config})

    plugin = AzulPluginOpenCTIFeed(azr_settings.parse_config(AzulPluginOpenCTIFeed, config))
    plugin.run_once()


if __name__ == "__main__":
    main()
