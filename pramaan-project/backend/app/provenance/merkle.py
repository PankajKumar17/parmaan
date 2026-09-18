import hashlib

from app.provenance.canonical import canonical_serialization


def _leaf_bytes(leaf):
    return leaf if isinstance(leaf, bytes) else canonical_serialization(leaf)


class MerkleTree(dict):
    def merkle_proof(self, index):
        levels = self["levels"]
        if not isinstance(index, int) or not levels or not 0 <= index < len(levels[0]):
            raise ValueError("leaf index is out of range")
        proof = []
        for level in levels[:-1]:
            sibling = index ^ 1
            if sibling >= len(level):
                sibling = index
            proof.append({"hash": level[sibling], "position": "left" if index % 2 else "right"})
            index //= 2
        return proof


def build_merkle_tree(leaves: list[bytes]) -> MerkleTree:
    level = [hashlib.sha256(_leaf_bytes(leaf)).hexdigest() for leaf in leaves]
    if not level:
        return MerkleTree(root=hashlib.sha256(b"").hexdigest(), levels=[])
    levels = [level]
    while len(level) > 1:
        paired = level + [level[-1]] if len(level) % 2 else level
        level = [hashlib.sha256(bytes.fromhex(paired[index]) + bytes.fromhex(paired[index + 1])).hexdigest()
                 for index in range(0, len(paired), 2)]
        levels.append(level)
    return MerkleTree(root=level[0], levels=levels)


def merkle_proof(tree, index):
    return MerkleTree(tree).merkle_proof(index)


def verify_proof(leaf, proof, root):
    try:
        if not isinstance(root, str) or len(root) != 64 or len(bytes.fromhex(root)) != 32:
            return False
        value = hashlib.sha256(_leaf_bytes(leaf)).digest()
        for step in proof:
            sibling = bytes.fromhex(step["hash"])
            if len(sibling) != 32 or step["position"] not in ("left", "right"):
                return False
            pair = sibling + value if step["position"] == "left" else value + sibling
            value = hashlib.sha256(pair).digest()
        return value.hex() == root.lower()
    except (TypeError, ValueError, KeyError):
        return False
