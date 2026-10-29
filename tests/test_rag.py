"""Tests for the RAG layer: chunking, the ChromaDB store, and the build."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import chromadb
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from netsentinel.rag import build_store
from netsentinel.rag.chunking import chunk_attack_technique, chunk_cve
from netsentinel.rag.store import RAGStore


def _cve(cve_id="CVE-2021-44228", desc="Remote code execution in Log4j.",
         metrics=None, weaknesses=None, lang="en"):
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "es", "value": "Descripcion."},
                         {"lang": lang, "value": desc}],
        "metrics": metrics or {},
        "weaknesses": weaknesses or [],
    }}


def _technique(technique_id="T1046", name="Network Service Discovery",
               description="Adversaries may scan for services. (Citation: X)",
               tactics=("discovery",), platforms=("Linux", "Windows")):
    refs = [{"source_name": "capec", "external_id": "CAPEC-1"}]
    if technique_id:
        refs.append({"source_name": "mitre-attack", "external_id": technique_id})
    return {
        "type": "attack-pattern",
        "name": name,
        "description": description,
        "external_references": refs,
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t}
                              for t in tactics]
                             + [{"kill_chain_name": "other", "phase_name": "ignored"}],
        "x_mitre_platforms": list(platforms),
    }


class TestChunkCve:
    def test_english_description_and_cvss_v31(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0},
                                      "baseSeverity": "CRITICAL"}]}
        chunk = chunk_cve(_cve(metrics=metrics))
        assert chunk["id"] == "CVE-2021-44228"
        assert chunk["document"] == "Remote code execution in Log4j."
        assert chunk["metadata"] == {"cve_id": "CVE-2021-44228",
                                     "severity": "critical", "cvss_score": 10.0}

    def test_newest_cvss_version_wins(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}],
        }
        meta = chunk_cve(_cve(metrics=metrics))["metadata"]
        assert (meta["severity"], meta["cvss_score"]) == ("critical", 9.8)

    def test_severity_falls_back_to_cvss_data(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5,
                                                   "baseSeverity": "HIGH"}}]}
        assert chunk_cve(_cve(metrics=metrics))["metadata"]["severity"] == "high"

    def test_no_metrics_is_unknown_with_zero_score(self):
        meta = chunk_cve(_cve())["metadata"]
        assert (meta["severity"], meta["cvss_score"]) == ("unknown", 0.0)

    def test_cwe_weaknesses_are_appended(self):
        weaknesses = [{"description": [{"value": "CWE-502"}, {"value": "NVD-CWE-Other"},
                                       {"value": "CWE-20"}]}]
        doc = chunk_cve(_cve(weaknesses=weaknesses))["document"]
        assert doc.endswith("Weaknesses: CWE-502, CWE-20")

    @pytest.mark.parametrize("entry", [
        {},
        _cve(cve_id=""),
        _cve(lang="fr"),
        _cve(desc="** REJECT ** Duplicate of CVE-2021-0001."),
    ])
    def test_unusable_entries_are_skipped(self, entry):
        assert chunk_cve(entry) is None


class TestChunkAttackTechnique:
    def test_builds_document_and_metadata(self):
        chunk = chunk_attack_technique(_technique())
        assert chunk["id"] == "T1046"
        assert chunk["document"] == (
            "T1046: Network Service Discovery. Adversaries may scan for services. "
            "(Ref: X) Tactics: discovery. Platforms: Linux, Windows."
        )
        assert chunk["metadata"] == {
            "technique_id": "T1046", "name": "Network Service Discovery",
            "is_sub_technique": False, "tactics": "discovery",
        }

    def test_sub_technique_and_hyphenated_tactic(self):
        chunk = chunk_attack_technique(
            _technique(technique_id="T1110.001", tactics=("credential-access",)))
        assert chunk["metadata"]["is_sub_technique"] is True
        assert chunk["metadata"]["tactics"] == "credential access"

    def test_tactics_and_platforms_are_optional(self):
        doc = chunk_attack_technique(_technique(tactics=(), platforms=()))["document"]
        assert "Tactics" not in doc and "Platforms" not in doc

    @pytest.mark.parametrize("kwargs", [
        {"technique_id": ""}, {"name": ""}, {"description": ""},
    ])
    def test_unusable_techniques_are_skipped(self, kwargs):
        assert chunk_attack_technique(_technique(**kwargs)) is None


class TestFormatResults:
    def test_pairs_documents_metadata_and_distances(self):
        results = {"documents": [["a", "b"]], "metadatas": [[{"k": 1}, {"k": 2}]],
                   "distances": [[0.1, 0.2]]}
        assert RAGStore._format_results(results) == [
            {"content": "a", "metadata": {"k": 1}, "distance": 0.1},
            {"content": "b", "metadata": {"k": 2}, "distance": 0.2},
        ]

    def test_missing_metadata_and_distances(self):
        assert RAGStore._format_results({"documents": [["a"]]}) == [
            {"content": "a", "metadata": {}, "distance": None},
        ]

    @pytest.mark.parametrize("results", [None, {}, {"documents": []}])
    def test_empty(self, results):
        assert RAGStore._format_results(results) == []


@pytest.fixture
def chroma_dir(tmp_path, monkeypatch):
    d = tmp_path / "chroma"
    monkeypatch.setattr(config, "CHROMA_DIR", d)
    return d


class TestStore:
    """Real ChromaDB in a temp dir, with its default local embedding model."""

    def test_missing_collections_return_no_results(self, chroma_dir):
        store = RAGStore(str(chroma_dir))
        assert store.query_cve("anything") == []
        assert store.query_attack("anything") == []

    def test_built_collections_are_searchable(self, chroma_dir):
        client = chromadb.PersistentClient(path=str(chroma_dir))
        build_store.build_collection(client, config.CHROMA_COLLECTION_ATTACK, [
            chunk_attack_technique(_technique()),
            chunk_attack_technique(_technique(
                technique_id="T1048", name="Exfiltration Over Alternative Protocol",
                description="Adversaries may steal data over DNS or FTP.",
                tactics=("exfiltration",))),
        ])

        results = RAGStore(str(chroma_dir)).query_attack("port scanning services", k=1)
        assert [r["metadata"]["technique_id"] for r in results] == ["T1046"]
        assert results[0]["distance"] is not None

    def test_rebuilding_replaces_the_collection(self, chroma_dir):
        client = chromadb.PersistentClient(path=str(chroma_dir))
        name = config.CHROMA_COLLECTION_CVE
        build_store.build_collection(client, name, [chunk_cve(_cve("CVE-1"))])
        build_store.build_collection(client, name, [chunk_cve(_cve("CVE-2"))])
        assert client.get_collection(name).get()["ids"] == ["CVE-2"]

    def test_large_builds_are_batched(self, chroma_dir, monkeypatch):
        added = []

        class FakeCollection:
            def add(self, ids, documents, metadatas):
                added.append(len(ids))

        class FakeClient:
            def delete_collection(self, name):
                raise ValueError("does not exist")

            def create_collection(self, name):
                return FakeCollection()

        chunks = [{"id": str(i), "document": "d", "metadata": {}} for i in range(250)]
        build_store.build_collection(FakeClient(), "c", chunks)
        assert added == [100, 100, 50]


class _Response:
    def __init__(self, payload=None, error=None):
        self._payload, self._error = payload, error

    def raise_for_status(self):
        if self._error:
            raise self._error

    def json(self):
        return self._payload


class TestFetch:
    def test_cves_are_deduplicated_across_keywords(self, monkeypatch):
        pages = {
            "a": {"vulnerabilities": [_cve("CVE-1"), _cve("CVE-2")]},
            "b": {"vulnerabilities": [_cve("CVE-2"), _cve("CVE-3"), {"cve": {}}]},
        }
        monkeypatch.setattr(build_store.time, "sleep", lambda s: None)
        monkeypatch.setattr(build_store.requests, "get",
                            lambda url, params, timeout: _Response(pages[params["keywordSearch"]]))
        ids = [c["cve"]["id"] for c in build_store.fetch_cves(["a", "b"])]
        assert ids == ["CVE-1", "CVE-2", "CVE-3"]

    def test_failed_keyword_does_not_stop_the_fetch(self, monkeypatch):
        def get(url, params, timeout):
            if params["keywordSearch"] == "bad":
                return _Response(error=RuntimeError("503"))
            return _Response({"vulnerabilities": [_cve("CVE-9")]})

        monkeypatch.setattr(build_store.time, "sleep", lambda s: None)
        monkeypatch.setattr(build_store.requests, "get", get)
        assert len(build_store.fetch_cves(["bad", "good"])) == 1

    def test_only_active_attack_patterns_are_kept(self, monkeypatch):
        bundle = {"objects": [
            {"type": "attack-pattern", "name": "keep"},
            {"type": "attack-pattern", "name": "revoked", "revoked": True},
            {"type": "attack-pattern", "name": "old", "x_mitre_deprecated": True},
            {"type": "malware", "name": "not a technique"},
        ]}
        monkeypatch.setattr(build_store.requests, "get",
                            lambda url, timeout: _Response(bundle))
        assert [t["name"] for t in build_store.fetch_attack_techniques()] == ["keep"]

    def test_attack_download_failure_returns_nothing(self, monkeypatch):
        def fail(url, timeout):
            raise ConnectionError("offline")

        monkeypatch.setattr(build_store.requests, "get", fail)
        assert build_store.fetch_attack_techniques() == []


class TestBuildStore:
    def test_builds_from_cached_raw_data(self, chroma_dir, tmp_path, monkeypatch):
        intel = tmp_path / "intel"
        intel.mkdir()
        (intel / "cves_raw.json").write_text(json.dumps([_cve(), _cve(cve_id="")]))
        (intel / "attack_techniques_raw.json").write_text(json.dumps([_technique()]))
        monkeypatch.setattr(config, "THREAT_INTEL_DIR", intel)

        build_store.build_store(use_cached=True)

        store = RAGStore(str(chroma_dir))
        assert [r["metadata"]["cve_id"] for r in store.query_cve("log4j")] == [
            "CVE-2021-44228"]
        assert store.query_attack("scan")[0]["metadata"]["technique_id"] == "T1046"

    def test_fresh_download_is_saved_and_empty_sets_are_skipped(
        self, chroma_dir, tmp_path, monkeypatch
    ):
        intel = tmp_path / "intel"
        monkeypatch.setattr(config, "THREAT_INTEL_DIR", intel)
        monkeypatch.setattr(build_store, "fetch_cves", lambda: [])
        monkeypatch.setattr(build_store, "fetch_attack_techniques", lambda: [])

        build_store.build_store()

        assert json.loads((intel / "cves_raw.json").read_text()) == []
        assert json.loads((intel / "attack_techniques_raw.json").read_text()) == []
        store = RAGStore(str(chroma_dir))
        assert store.query_cve("x") == [] and store.query_attack("x") == []
