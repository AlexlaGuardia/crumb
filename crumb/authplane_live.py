"""
Live federation against a real AuthPlane authorization server.

Unlike `authplane_demo`, nothing here is shaped by hand. A real AS mints the
token, signs it with its own key, publishes that key in its own JWKS, and Crumb
discovers the key from the issuer's metadata and verifies against it. The only
thing this file asserts is what actually came back.

Run it:

    export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
    export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
    docker run -d --name authplane -p 127.0.0.1:9000:9000 -p 127.0.0.1:9001:9001 \
      -e AUTHPLANE_ADMIN_API_KEY -e AUTHPLANE_SESSION_SECRET \
      -e AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true \
      -e AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true \
      -v authserver-data:/data authplane/authserver:latest serve

    python -m crumb.authplane_live

It provisions its own resource and client, so a clean container is enough.

WHAT IT DOES NOT COVER, on purpose: the delegated multi-hop case. AuthPlane
gates token exchange behind explicit consent (`consent_required` plus a
`consent_url`), which is the correct call on their part and means a delegation
chain cannot be minted headlessly. So the token here is client_credentials —
a service account, no `act`, no human. That is not a limitation of the demo, it
IS the gap: a real AS, a real signed token, and no way to name a person.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import jwt

from .federation import Federation, UnknownSigningKey, UntrustedIssuer
from .ledger import Ledger
from .tokens import resolve_actor
from .verify import verify_ledger

AS = os.environ.get("AUTHPLANE_URL", "http://127.0.0.1:9000")
ADMIN = os.environ.get("AUTHPLANE_ADMIN_URL", "http://127.0.0.1:9001/admin")
ISSUER = os.environ.get("AUTHPLANE_ISSUER", "http://localhost:9000")
ADMIN_KEY = os.environ.get("AUTHPLANE_ADMIN_API_KEY", "")
RESOURCE = "https://mcp.example.com/mcp"
SCOPE = "tools/query"
LEDGER, KEY, PUB = "data/authplane_live.jsonl", "data/authplane_live.key", "data/authplane_live.pub"
LINE = "─" * 74


def _req(url: str, method: str = "GET", body: dict | None = None,
         form: dict | None = None, admin: bool = False) -> dict:
    data, headers = None, {}
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if admin:
        headers["Authorization"] = f"Bearer {ADMIN_KEY}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return _decode(r.read().decode())
    except urllib.error.HTTPError as e:
        out = _decode(e.read().decode())
        return {**out, "_status": e.code} if isinstance(out, dict) else {
            "_status": e.code, "_body": out}


def _decode(raw: str):
    """Not every error body is JSON. This server answers an unrouted admin path
    with plain `404 page not found`, and a decoder that assumes JSON turns a
    clear 404 into a JSONDecodeError three frames from where it happened."""
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        return raw.strip()


def _provision() -> tuple[str, str]:
    """Create the resource and a client, and authorize the client against it.

    Three separate grants are required and they are not interchangeable: the
    resource must exist, the client must be listed in the resource's policy, and
    the client must hold the scope. Miss any one and the token endpoint answers
    `invalid_scope` without saying which.
    """
    existing = _req(f"{ADMIN}/resources", admin=True)
    match = [r for r in existing if r.get("uri") == RESOURCE] if isinstance(existing, list) else []
    if match:
        res = match[0]
    else:
        res = _req(f"{ADMIN}/resources", "POST", admin=True, body={
            "uri": RESOURCE, "slug": "records-mcp", "backend_kind": "mint",
            "scopes": [{"name": SCOPE}]})
        if "id" not in res:
            sys.exit(f"could not create resource: {res}")

    client = _req(f"{AS}/oauth/register", "POST", body={
        "client_name": "crumb-gateway",
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_post"})
    cid, csec = client["client_id"], client["client_secret"]

    # The scope grant. This write takes effect but is not echoed back by any GET
    # on the client, so there is no way to confirm it except by minting a token.
    _req(f"{ADMIN}/clients/{cid}", "PATCH", admin=True,
         body={"scopes": [{"name": SCOPE}]})
    policy = res.get("policy", {})
    allowed = set(policy.get("exchange", {}).get("allowed_client_ids", [])) | {cid}
    runtime = set(policy.get("runtime", {}).get("client_ids", [])) | {cid}
    _req(f"{ADMIN}/resources/{res['id']}", "PATCH", admin=True, body={"policy": {
        "exchange": {"allowed_client_ids": sorted(allowed)},
        "runtime": {"client_ids": sorted(runtime)}}})
    return cid, csec


def main() -> None:
    if not ADMIN_KEY:
        sys.exit("set AUTHPLANE_ADMIN_API_KEY to the value the container was started with")
    if "_status" in _req(f"{AS}/.well-known/oauth-authorization-server"):
        sys.exit(f"no authorization server reachable at {AS} — is the container up?")

    print(LINE)
    print(f"  authorization server: {AS}")
    print(LINE)

    cid, csec = _provision()
    print(f"\n  provisioned resource {RESOURCE}")
    print(f"  provisioned client   {cid}")

    grant = _req(f"{AS}/oauth/token", "POST", form={
        "grant_type": "client_credentials", "client_id": cid,
        "client_secret": csec, "resource": RESOURCE})
    if "access_token" not in grant:
        sys.exit(f"token request refused: {grant}")
    token = grant["access_token"]
    header = jwt.get_unverified_header(token)
    print(f"\n  token minted by the AS: alg={header['alg']} typ={header.get('typ')} "
          f"kid={header['kid']}")

    # Trust the issuer by NAME and let its own metadata say where the keys live.
    fed = Federation().trust_discovery(
        ISSUER, discovery_url=f"{AS}/.well-known/oauth-authorization-server")
    key = fed.key_for(ISSUER, header["kid"])
    print(f"  key fetched live from the issuer's advertised jwks_uri "
          f"({type(key).__name__})")

    claims = jwt.decode(token, key, algorithms=["RS256", "ES256"],
                        audience=RESOURCE, issuer=ISSUER)
    print("  VERIFIED against the live JWKS. No shared secret, no pinned PEM.")

    actor = resolve_actor(claims)
    print(f"\n  resolved   human={actor['human']!r}  agent={actor['agent']!r}  "
          f"actor_type={actor['actor_type']!r}")

    ledger = Ledger(path=LEDGER, key_path=KEY)
    ledger.reset()
    rec = ledger.append({
        "actor_identity": actor["human"],
        "agent_id": actor["agent"],
        "action": "read_record",
        "resource_id": {"record_id": 42},
        "on_behalf_assertion": "delegated" if actor["human"] else "service-account",
        "outcome": "success", "transport": "mcp",
        "claim_source": actor["source"], "issuer": claims["iss"],
    })
    r = verify_ledger(LEDGER, PUB)
    print(f"  crumb #{rec['seq']} written; ledger {'VERIFIED' if r.ok else 'MISMATCH'} "
          f"({r.checked} entries)")

    # The trust set is only meaningful if it also refuses.
    for label, args in (("unknown kid", (ISSUER, "kid-the-issuer-never-published")),
                        ("unnamed issuer", ("https://evil.example.com", header["kid"]))):
        try:
            fed.key_for(*args)
            print(f"  !! {label} was ACCEPTED — fail-closed is broken")
        except (UnknownSigningKey, UntrustedIssuer) as e:
            print(f"  {label} refused ({type(e).__name__})")

    print("\n" + LINE)
    print("  A real AS, its own key, discovered and verified live. And the record")
    print("  still cannot name a person, because a client-credentials token never")
    print("  carried one. Mint-time provenance and call-time attribution are two")
    print("  different records; this is what it looks like when only one exists.")
    print(LINE)


if __name__ == "__main__":
    main()
