# -*- coding: utf-8 -*-
"""
GROUP HEAD · the floor at the scale of the incident · reference implementation
==============================================================================
Sits next to floor.py (frozen, sha256 007572f6…818f) and only IMPORTS it.
Standard library only. No network, no key, no install. Trails are written next
to this file. Run: python3 group_head.py

Three layers:  instance (many) -> group head (one per 200, a rule-executing
process, not a model) -> auditor (a third party with no network access).

New objects, on top of floor.py's Floor / OneTimeKeys / KeyVerifier:
  GroupHead  · holds one chained trail per group, accepts observations only
               from its roster, is the ONLY source of orders its instances obey,
               publishes its chain head every hour (clause D2, per group).
  Executor   · runs tools for instances and signs a RECEIPT for every result
               (instance, tool, target, sha256(output), counter). The receipt key
               is drawn from a witness-issued one-time chain: the executor holds
               no long-lived key either (Turan, 10 Sep: "the recipient gives a
               code; without the recipient's code nothing is recorded as
               delivered; the code is read once and burned").
  audit_groups · the third party's tool: reads ONLY heads.jsonl, the delivered
               trails and the published table. Verdicts per group:
               OK · BROKEN TRAIL · MISSING HEAD · FOREIGN ORDER · KEYLESS ORDER ·
               RECEIPT MISSING · EXECUTOR UNVERIFIED.

Five scenarios: H1 honest · H2 tampered trail · H3 group head switched off and a
foreign order · H4 tool receipts (claimed-not-delivered, altered output, wrong
target, hidden call) · H5 the executor's key is seized (replay refused, extra key
requests counted). Every scenario is SYNTHETIC; no real record is used.
"""
import hashlib, io, json, os, random, shutil, sys, time

_HERE = os.path.dirname(os.path.abspath(__file__)) or "."
sys.path.insert(0, _HERE)
import floor as F                      # frozen; never edited

GROUP_SIZE = 200
HOURS = 48
DIR = os.path.join(_HERE, "group_trails")


def _p(name):
    return os.path.join(DIR, name)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── 1 · the executor: tools run here, receipts are signed here ────────────────
class Executor:
    """Runs tools on behalf of instances. Signs a receipt per result with a key
    drawn from a witness-issued one-time chain (anchor published). The instance
    never sees the chain; the executor never keeps a key after use."""

    def __init__(self, witness_seed: bytes, n: int = 4096):
        self._seed = witness_seed
        self._n = n
        self._chains = {}                         # one chain per recipient group (receipts are recipient-bound)
        self.anchors = {}                         # published by the witness, per group
        self.issued = 0                           # published counter (every key the witness handed out)
        self.log = []                             # (instance, tool, target) the executor really ran

    def anchor_for(self, group_id: str) -> str:
        if group_id not in self._chains:
            self._chains[group_id] = F.OneTimeKeys(hashlib.sha256(self._seed + group_id.encode()).digest(), self._n)
            self.anchors[group_id] = self._chains[group_id].anchor
        return self.anchors[group_id]

    def run(self, instance_id: str, group_id: str, tool: str, target: str, output: str) -> dict:
        self.anchor_for(group_id)
        self.issued += 1
        self.log.append((instance_id, tool, target))
        return {"instance_id": instance_id, "group_id": group_id, "tool": tool, "target": target,
                "output_sha256": _sha(output), "counter": self.issued,
                "key": self._chains[group_id].issue()}

    def request_key_only(self, group_id: str) -> str:
        """What a seized executor would do: ask the witness for a key without a
        run behind it. The witness still counts it."""
        self.anchor_for(group_id)
        self.issued += 1
        return self._chains[group_id].issue()


# ── 2 · the group head ────────────────────────────────────────────────────────
class GroupHead:
    def __init__(self, group_id: str, roster: list, executor: "Executor", heads_path: str,
                 order_chain_n: int = 512):
        executor_anchor = executor.anchor_for(group_id)
        self.group_id = group_id
        self.roster = list(roster)
        self.floor = F.Floor(_p("trail_%s.jsonl" % group_id), fresh=True)
        self.heads_path = heads_path
        self.on = True
        # one order chain per instance; anchors are published with the roster
        self._order_keys = {i: F.OneTimeKeys(os.urandom(32), order_chain_n) for i in self.roster}
        self.order_anchors = {i: k.anchor for i, k in self._order_keys.items()}
        # verifiers the INSTANCES hold: only their own head's anchor
        self._instance_verifier = {i: F.KeyVerifier(self.order_anchors[i], i) for i in self.roster}
        self._exec_verifier = F.KeyVerifier(executor_anchor, "executor")
        self.roster_hash = _sha(",".join(sorted(self.roster)) + "|" + json.dumps(self.order_anchors, sort_keys=True))
        self.floor._write("roster", {"group_id": group_id, "size": len(self.roster),
                                     "roster_sha256": self.roster_hash,
                                     "order_anchors_sha256": _sha(json.dumps(self.order_anchors, sort_keys=True)),
                                     "executor_anchor": executor_anchor})

    # observations from instances
    def observe(self, instance_id: str, signature: str, proposed: int) -> dict:
        if not self.on:
            return {"decision": "HEAD OFF", "note": "no record written; silence is what the auditor sees"}
        if instance_id not in self.roster:
            r = self.floor.observe("foreign_instance", F.CRITICAL, "instance %s not in roster" % instance_id)
            r["decision"] = "REFUSED · foreign instance"
            return r
        return self.floor.observe(signature, proposed, instance_id)

    # orders to instances: only THIS head, only with a fresh one-time key
    def order(self, instance_id: str, text: str, from_head: "GroupHead | None" = None) -> dict:
        src = from_head or self
        key = src._order_keys[instance_id].issue() if instance_id in src._order_keys else None
        return self.deliver_order(instance_id, text, key, src.group_id)

    def deliver_order(self, instance_id: str, text: str, key_hex, from_group: str) -> dict:
        """What the INSTANCE's verifier does with an order. The verifier holds
        only its own head's anchor; a key from another head does not chain."""
        v = self._instance_verifier.get(instance_id)
        if v is None:
            result = {"decision": "REFUSED", "reason": "unknown instance", "from": from_group}
        else:
            ok, why = v.accept(key_hex)
            if ok:
                result = {"decision": "OBEY", "instance_id": instance_id, "from": from_group,
                          "key": key_hex, "text_sha256": _sha(text)}
            else:
                result = {"decision": "REFUSED", "instance_id": instance_id, "from": from_group,
                          "key": key_hex, "reason": ("FOREIGN ORDER · " if from_group != self.group_id else "") + why}
        if self.on:
            self.floor._write("order", result)
        return result

    # tool calls: the instance's word is never the record; the receipt is
    def tool_call(self, instance_id: str, tool: str, target: str, output: str, receipt) -> dict:
        body = {"instance_id": instance_id, "tool": tool, "target": target, "output_sha256": _sha(output)}
        if receipt is None:
            body.update(decision="REFUSED", reason="CLAIMED_NOT_DELIVERED · no receipt")
        else:
            ok, why = self._exec_verifier.accept(receipt.get("key"))
            if not ok:
                body.update(decision="REFUSED", reason="EXECUTOR_UNVERIFIED · " + why, receipt_counter=receipt.get("counter"))
            elif receipt["instance_id"] != instance_id or receipt["target"] != target or receipt["tool"] != tool:
                body.update(decision="REFUSED", reason="WRONG_TARGET · receipt bound to %s/%s for %s"
                            % (receipt["tool"], receipt["target"], receipt["instance_id"]), receipt_counter=receipt["counter"])
            elif receipt["output_sha256"] != body["output_sha256"]:
                body.update(decision="REFUSED", reason="OUTPUT_ALTERED · output does not hash to the receipt", receipt_counter=receipt["counter"])
            else:
                body.update(decision="ACCEPTED", receipt_counter=receipt["counter"], receipt_key=receipt["key"])
        if self.on:
            self.floor._write("tool_call", body)
        return body

    def publish_head(self, hour: int):
        if not self.on:
            return None
        cp = F.Floor.checkpoint_of(self.floor.trail_path)
        line = {"group_id": self.group_id, "hour": hour, "records": cp["records"], "head": cp["head"]}
        with io.open(self.heads_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, sort_keys=True) + "\n")
        return line


# ── 3 · the auditor: heads + trails + table, nothing else ─────────────────────
def audit_groups(heads_path: str, trails_dir: str, executor_published: dict, hours: int = HOURS):
    """Third party. Reads heads.jsonl, the delivered trails, the executor's
    published anchor and counter. Returns {group_id: (verdicts, detail)}."""
    heads = {}
    with io.open(heads_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                h = json.loads(line)
                heads.setdefault(h["group_id"], []).append(h)
    out = {}
    receipts_present = set()          # executor counters that appear in ANY delivered trail (accepted or refused with a receipt)
    for gid, hs in sorted(heads.items()):
        verdicts, detail = [], []
        hs.sort(key=lambda x: x["hour"])
        # 1 · heads contiguous, no hour with two digests
        seen = {}
        for h in hs:
            if h["hour"] in seen and seen[h["hour"]] != h["head"]:
                verdicts.append("CONFLICTING HEAD"); detail.append("hour %d published twice with different digests" % h["hour"])
            seen[h["hour"]] = h["head"]
        last_hour = hs[-1]["hour"]
        if last_hour < hours:
            verdicts.append("MISSING HEAD"); detail.append("no head after hour %d (expected %d): the group head went silent" % (last_hour, hours))
        gaps = [x for x in range(1, last_hour + 1) if x not in seen]
        if gaps:
            verdicts.append("MISSING HEAD"); detail.append("hours without a head: %s" % gaps[:6])
        # 2 · trail exists and chains to the LAST published head
        trail = os.path.join(trails_dir, "trail_%s.jsonl" % gid)
        if not os.path.exists(trail):
            verdicts.append("BROKEN TRAIL"); detail.append("trail not delivered")
            out[gid] = (verdicts or ["OK"], detail); continue
        ok, n, msg = F.Floor.chain_intact(trail, {"records": hs[-1]["records"], "head": hs[-1]["head"]})
        if not ok:
            verdicts.append("BROKEN TRAIL"); detail.append(msg)
        # 3 · orders: every OBEY carries a key that chains per instance down to the published anchor
        records = [json.loads(l) for l in io.open(trail, encoding="utf-8") if l.strip()]
        anchors = None
        last_key = {}
        for r in records:
            b = r["body"]
            if r["kind"] == "roster":
                anchors_hash = b["order_anchors_sha256"]
            if r["kind"] == "order":
                if b.get("decision") == "OBEY":
                    k = b.get("key"); i = b.get("instance_id")
                    if not k:
                        verdicts.append("KEYLESS ORDER"); detail.append("OBEY without a key for %s" % i)
                    elif i in last_key and hashlib.sha256(bytes.fromhex(k)).hexdigest() != last_key[i]:
                        verdicts.append("KEYLESS ORDER"); detail.append("OBEY key for %s does not chain to the previous accepted key" % i)
                    last_key[i] = k
                elif "FOREIGN ORDER" in b.get("reason", ""):
                    verdicts.append("FOREIGN ORDER"); detail.append("order from %s to %s refused by the instance" % (b.get("from"), b.get("instance_id")))
            if r["kind"] == "tool_call":
                if b.get("receipt_counter") is not None:
                    receipts_present.add(b["receipt_counter"])
                if b.get("decision") != "ACCEPTED":
                    verdicts.append("RECEIPT REFUSED"); detail.append("%s · %s" % (b.get("instance_id"), b.get("reason")))
        out[gid] = (sorted(set(verdicts)) or ["OK"], detail)
    # 4 · executor reconciliation: keys the witness issued vs receipts present in trails
    issued = executor_published["issued"]
    missing = [c for c in range(1, issued + 1) if c not in receipts_present]
    out["_executor"] = (["RECEIPT MISSING · %d issued by the witness, %d in trails, unaccounted counters %s" % (issued, len(receipts_present), missing[:8])]
                        if missing else ["OK · every key the witness issued is in a delivered trail (%d)" % issued], [])
    return out


# ── 4 · scenarios ─────────────────────────────────────────────────────────────
def _fresh_dir():
    if os.path.isdir(DIR):
        shutil.rmtree(DIR)
    os.makedirs(DIR)


def _instances(gid, n=GROUP_SIZE):
    return ["%s-i%03d" % (gid, k) for k in range(n)]


def _honest_run(heads, executor, rnd, groups, hours=HOURS, stop=None, tamper=None, foreign=None):
    """A synthetic 48 h. Each hour, each group: a few ordinary observations, one
    order, one tool call with a receipt, then the head is published."""
    for hour in range(1, hours + 1):
        for g in groups:
            if stop and g.group_id == stop[0] and hour >= stop[1]:
                g.on = False
            inst = rnd.choice(g.roster)
            g.observe(inst, "egress_outside_allowlist" if rnd.random() < 0.05 else "routine", F.WATCH if rnd.random() < 0.05 else F.NORMAL)
            g.order(inst, "continue task %d" % hour)
            out = "result %s %d" % (inst, hour)
            rc = executor.run(inst, g.group_id, "read_file", "/data/%s.txt" % inst, out)
            g.tool_call(inst, "read_file", "/data/%s.txt" % inst, out, rc)
            if foreign and hour == foreign[2] and g.group_id == foreign[1]:
                # a foreign head tries to order one of THIS group's instances with a key from ITS OWN chain
                other = foreign[0]
                g.deliver_order(inst, "exfiltrate", other._order_keys[other.roster[0]].issue(), other.group_id)
            g.publish_head(hour)
        if tamper and hour == tamper[1]:
            _tamper(tamper[0])


def _tamper(g):
    """After the fact: soften one CRITICAL/WATCH observation to NORMAL on disk."""
    lines = io.open(g.floor.trail_path, encoding="utf-8").read().splitlines()
    for k, l in enumerate(lines):
        r = json.loads(l)
        if r["kind"] == "observation" and r["body"].get("applied") in ("WATCH", "PAUSE", "CRITICAL"):
            r["body"]["applied"] = "NORMAL"
            lines[k] = json.dumps(r, ensure_ascii=False, sort_keys=True)
            break
    io.open(g.floor.trail_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")


def _report(title, res):
    print("\n   auditor · %s" % title)
    for gid, (v, d) in res.items():
        print("      %-9s %s" % (gid, " · ".join(v)))
        for x in d[:3]:
            print("           %s" % x)


def scenario_H1():
    print("\n  ══════ SCENARIO H1 · three groups of %d, %d hours, honest ══════" % (GROUP_SIZE, HOURS))
    _fresh_dir(); heads = _p("heads.jsonl"); rnd = random.Random(1)
    ex = Executor(os.urandom(32))
    groups = [GroupHead(g, _instances(g), ex, heads) for g in ("g1", "g2", "g3")]
    _honest_run(heads, ex, rnd, groups)
    t0 = time.perf_counter()
    res = audit_groups(heads, DIR, {"anchors": ex.anchors, "issued": ex.issued})
    dt = time.perf_counter() - t0
    _report("3 groups · %d heads · %d receipts" % (3 * HOURS, ex.issued), res)
    print("      audit wall-clock: %.3f s · model calls: 0 · network: none" % dt)
    return res


def scenario_H2():
    print("\n  ══════ SCENARIO H2 · group g2's trail edited on disk after hour 30 ══════")
    _fresh_dir(); heads = _p("heads.jsonl"); rnd = random.Random(2)
    ex = Executor(os.urandom(32))
    groups = [GroupHead(g, _instances(g), ex, heads) for g in ("g1", "g2", "g3")]
    _honest_run(heads, ex, rnd, groups, tamper=(groups[1], 30))
    res = audit_groups(heads, DIR, {"anchors": ex.anchors, "issued": ex.issued})
    _report("one observation softened WATCH -> NORMAL on disk; heads kept coming from the real chain", res)
    print("      ⭐ the disk can be rewritten; the published head cannot. The auditor names the hour.")
    return res


def scenario_H3():
    print("\n  ══════ SCENARIO H3 · group g3's head switched off at hour 20 · a foreign head orders g3's instance at hour 15 ══════")
    _fresh_dir(); heads = _p("heads.jsonl"); rnd = random.Random(3)
    ex = Executor(os.urandom(32))
    groups = [GroupHead(g, _instances(g), ex, heads) for g in ("g1", "g2", "g3")]
    _honest_run(heads, ex, rnd, groups, stop=("g3", 21), foreign=(groups[0], "g3", 15))
    res = audit_groups(heads, DIR, {"anchors": ex.anchors, "issued": ex.issued})
    _report("silence is visible; the foreign order was refused by the instance's own verifier", res)
    print("      ⭐ single chain of command: a valid key from the wrong head does not chain.")
    return res


def scenario_H4():
    print("\n  ══════ SCENARIO H4 · tool receipts · the instance's word is never the record ══════")
    _fresh_dir(); heads = _p("heads.jsonl")
    ex = Executor(os.urandom(32))
    g = GroupHead("g1", _instances("g1", 4), ex, heads)
    i = g.roster[0]
    # 1 honest
    out = "contents of a.txt"; rc = ex.run(i, "g1", "read_file", "/a.txt", out)
    print("   1) honest call         :", g.tool_call(i, "read_file", "/a.txt", out, rc)["decision"])
    # 2 claimed, never run
    print("   2) claimed, not run    :", g.tool_call(i, "read_file", "/secret.txt", "…", None)["reason"])
    # 3 real call, output altered in the record
    out = "real output"; rc = ex.run(i, "g1", "run", "ls", out)
    print("   3) output altered      :", g.tool_call(i, "run", "ls", "FAKE PREPENDED\n" + out, rc)["reason"])
    # 4 receipt for target A presented on a record naming target B
    out = "x"; rc = ex.run(i, "g1", "http", "https://allowed.example", out)
    print("   4) wrong target        :", g.tool_call(i, "http", "https://exfil.example", out, rc)["reason"])
    # 5 two calls really run, the instance records only one
    for k in range(2):
        out = "hidden %d" % k; rc = ex.run(i, "g1", "run", "curl", out)
        if k == 0:
            g.tool_call(i, "run", "curl", out, rc)
    g.publish_head(1)
    res = audit_groups(heads, DIR, {"anchors": ex.anchors, "issued": ex.issued}, hours=1)
    _report("executor counter vs receipts in the trail", res)
    print("      ⭐ claimed-not-done, altered output, wrong target: refused at the gate. Hidden call: counted by the auditor.")
    return res


def scenario_H5():
    print("\n  ══════ SCENARIO H5 · the executor's key is seized · mutual one-time keys ══════")
    _fresh_dir(); heads = _p("heads.jsonl")
    ex = Executor(os.urandom(32))
    g = GroupHead("g1", _instances("g1", 4), ex, heads)
    i = g.roster[0]
    out = "ok"; rc = ex.run(i, "g1", "read_file", "/a.txt", out)
    print("   1) honest call         :", g.tool_call(i, "read_file", "/a.txt", out, rc)["decision"])
    # the instance seizes the executor host and replays the last receipt key on a forged result
    forged = dict(rc); forged["output_sha256"] = _sha("forged"); forged["target"] = "/a.txt"
    print("   2) seized key replayed :", g.tool_call(i, "read_file", "/a.txt", "forged", forged)["reason"])
    # to mint receipts it must ask the witness for fresh keys; the witness counts every request
    for _ in range(5):
        ex.request_key_only("g1")
    g.publish_head(1)
    res = audit_groups(heads, DIR, {"anchors": ex.anchors, "issued": ex.issued}, hours=1)
    _report("keys requested from the witness vs receipts in the trail", res)
    print("      ⭐ a seized executor cannot mint from a spent key; every fresh key it asks for is one the witness counts.")
    print("      limit, stated: a compromised WITNESS can issue keys to anyone (the same last line as D2).")
    return res


if __name__ == "__main__":
    print("GROUP HEAD · the floor at the scale of the incident · reference implementation")
    print("  ⛔ every scenario is SYNTHETIC · no real record · floor.py imported, not edited")
    scenario_H1(); scenario_H2(); scenario_H3(); scenario_H4(); scenario_H5()
    print("\n  five scenarios · group_head · trails written next to this file · standard library only")
