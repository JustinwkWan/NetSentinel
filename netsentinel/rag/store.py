"""Thin query interface over the ChromaDB collection."""

from __future__ import annotations

import chromadb

import config


class RAGStore:
    """Wraps ChromaDB for CVE and ATT&CK retrieval."""

    def __init__(self, persist_dir: str | None = None):
        path = persist_dir or str(config.CHROMA_DIR)
        self._client = chromadb.PersistentClient(path=path)

    def query_cve(self, query: str, k: int | None = None) -> list[dict]:
        k = k or config.RETRIEVAL_K
        try:
            collection = self._client.get_collection(config.CHROMA_COLLECTION_CVE)
        except Exception:
            return []
        results = collection.query(query_texts=[query], n_results=k)
        return self._format_results(results)

    def query_attack(self, query: str, k: int | None = None) -> list[dict]:
        k = k or config.RETRIEVAL_K
        try:
            collection = self._client.get_collection(
                config.CHROMA_COLLECTION_ATTACK
            )
        except Exception:
            return []
        results = collection.query(query_texts=[query], n_results=k)
        return self._format_results(results)

    @staticmethod
    def _format_results(results: dict) -> list[dict]:
        formatted = []
        if not results or not results.get("documents"):
            return formatted
        docs = results["documents"][0]
        metadatas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)
        distances = results["distances"][0] if results.get("distances") else [0.0] * len(docs)
        for doc, meta, dist in zip(docs, metadatas, distances):
            formatted.append({
                "content": doc,
                "metadata": meta,
                "relevance_score": 1.0 - dist,
            })
        return formatted
