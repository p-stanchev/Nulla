# Automatic Relay (No Manual IPs)

This document captures the planned automatic relay flow for Nulla’s P2P layer. The goal is to let nodes behind NAT or closed ports receive inbound traffic **without** opening router ports and **without** relay operators configuring target IPs. A seed/operator can simply run with `--relay-auto` (or env `NULLA_RELAY_AUTO=1`) and the node will self-configure.

## Goals

- Make inbound reachability opt-in for nodes that cannot accept direct sockets.
- Avoid manual relay targeting; everything derives from the existing outbound connection.
- Keep the feature optional and bounded by clear safety limits.
- Maintain compatibility with the current header-first protocol (no consensus changes).

## Capability Handshake

Two capability bits are exchanged during the initial version handshake:

- `REQUEST_RELAY`: set by nodes that cannot accept inbound connections and want a relay slot.
- `PROVIDE_RELAY`: set by nodes willing to serve as relays.
  - Client knob: `--request-relay` (or `NULLA_REQUEST_RELAY=1`).
  - Server knob: `--relay-auto` (or `NULLA_RELAY_AUTO=1`) together with `--relay-cap <N>`.

Example handshake payload:

```text
version {
  version,
  node_id,
  flags: [REQUEST_RELAY]
}
```

Relays do not ask for or store external IPs; the slot is tied to the active outbound socket.

## Relay Slot Lifecycle

When a relay-capable node receives a connection with `REQUEST_RELAY`:

1) **Capacity check**: accept only if below `--relay-cap` (default 0 / off). Slots are only opened automatically when `--relay-auto` is set. If no cap is provided, the node does **not** relay (safe-by-default).
2) **Grant**: assign a `slot_id` and remember `{slot_id, peer_node_id, connection_handle, last_activity}`.
3) **Map to socket**: the slot always routes over the already-established TCP/WebSocket connection.
4) **Refresh/idle timeout**: expire slots after ~10–15 minutes of inactivity.
5) **Disconnect cleanup**: drop the slot immediately if the underlying connection closes.

If the relay is at capacity, it refuses the slot and keeps the connection as a normal peer (no relay service).

## Connection-Derived Routing

- The relay never collects IPs or asks the requester for a listen address.
- Inbound traffic destined for a relayed node is addressed by `node_id`:
  - peer → relay: `RelayFrame { slot_id, payload }`
  - relay → target: forward the payload over the mapped connection
- From the network’s perspective, relayed nodes gossip, exchange headers/blocks/txs, and are addressed just like directly reachable peers.

## Safety Controls

- **Hard cap**: `--relay-cap <N>` (default 0/off).
- **Idle timeout**: close inactive slots (10–15 minutes).
- **Rate limits**: bound relay open attempts per IP/node_id to avoid abuse.
- **Explicit opt-in**: both REQUEST and PROVIDE flags must be present before any relay slot is created.
- **Logging**: `relay granted`, `relay refused (cap reached)`, `relay expired`.

## Operational Flow

1. NAT’d node dials outbound with `REQUEST_RELAY` set.
2. Relay-capable peer with spare capacity sets `PROVIDE_RELAY` **automatically** when started with `--relay-auto` and grants a slot (subject to `--relay-cap`).
3. Relay advertises reachability by node_id (no IPs).
4. Other peers address the relayed node via the relay using `slot_id` and node_id derived routing.
5. Slots expire automatically if idle or when the underlying socket drops.

This approach is intentionally lightweight: it reuses the existing authenticated P2P connection to carry relayed traffic, removes any need for manual IP input, and keeps relaying bounded and opt-in by default.
