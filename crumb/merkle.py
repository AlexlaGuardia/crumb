"""
Merkle tree over the crumb chain (RFC 6962 style).

The hash chain (ledger.py) makes a *careless* edit detectable — but it can't stop
the operator who holds the signing key. They can re-hash and re-sign every entry
after the one they changed, and `verify` will pass the forged chain (see
anchor_demo). The defense is to commit the whole log to a single Merkle root and
anchor THAT root somewhere the operator doesn't control (anchor.py).

This module builds the tree, computes the root, and produces/checks compact
inclusion proofs — so you can prove one crumb is in an anchored log without
shipping the whole ledger. Domain-separated hashing (0x00 leaf / 0x01 node) per
RFC 6962, so a leaf can never be reinterpreted as an interior node.
"""

from __future__ import annotations

import hashlib


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _level_up(nodes: list[bytes]) -> list[bytes]:
    """One level of the tree. Odd node carries up unchanged (RFC 6962)."""
    out = []
    for i in range(0, len(nodes) - 1, 2):
        out.append(_node_hash(nodes[i], nodes[i + 1]))
    if len(nodes) % 2:
        out.append(nodes[-1])
    return out


def _root_bytes(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    nodes = [_leaf_hash(d) for d in leaves]
    while len(nodes) > 1:
        nodes = _level_up(nodes)
    return nodes[0]


def root(leaves: list[bytes]) -> str:
    """Merkle root over leaf-data byte strings, as hex. Empty tree → sha256('')."""
    return _root_bytes(leaves).hex()


def _largest_pow2_less(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, bool]]:
    """Audit path proving leaves[index] is in the tree. Each step is
    (sibling_hash_hex, sibling_is_left). RFC 6962 split (largest power of two),
    direction-tagged so verification needs no index arithmetic."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")

    def path(m: int, d: list[bytes]) -> list[tuple[str, bool]]:
        n = len(d)
        if n == 1:
            return []
        k = _largest_pow2_less(n)
        if m < k:                                    # leaf in left subtree
            return path(m, d[:k]) + [(_root_bytes(d[k:]).hex(), False)]
        return path(m - k, d[k:]) + [(_root_bytes(d[:k]).hex(), True)]

    return path(index, leaves)


def verify_proof(leaf: bytes, proof: list[tuple[str, bool]], expected_root: str) -> bool:
    """Recompute the root from one leaf + its audit path; compare to expected."""
    h = _leaf_hash(leaf)
    for sib_hex, sib_is_left in proof:
        sib = bytes.fromhex(sib_hex)
        h = _node_hash(sib, h) if sib_is_left else _node_hash(h, sib)
    return h.hex() == expected_root
