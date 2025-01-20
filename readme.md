Deep Space Quinn Workbench 2
============================

A command-line application to simulate QUIC connections in different scenarios (network
topology and QUIC parameters). The simulation creates a single connection, issues a fixed
number of requests from the client to the server, and streams the server's responses back to the
client.

_Note: for the previous version of quinn workbench go to [this
branch](https://github.com/aochagavia/quinn-workbench/tree/v1)._

## Features

- Pure. No IO operations are made, everything happens in-memory within a single process.
- Time warping. The simulation's internal clock advances automatically to the next event, making the
  simulation complete in an instant (even in the presence of deep-space-like RTTs).
- Deterministic. Two runs with the same parameters yield the same output.
- Inspectable. Next to informative command-line output and statistics, the application generates a
  synthetic pcap file, so you can examine the traffic in more detail using Wireshark.
- Configurable network settings and QUIC parameters through reusable JSON config files (see
  `test-data` and [JSON config details](#json-config-details)).
- Configurable simulation behavior through command-line arguments (see `cargo run --release --
  --help`).

## Getting started

After [installing Rust](https://rustup.rs/), you can get started with:

```bash
cargo run --release -- \
  --quinn-config test-data/earth-mars/quinn.json \
  --network-graph test-data/earth-mars/networkgraph-5nodes.json \
  --network-events test-data/earth-mars/events.json \
  --client-ip-address 192.168.40.1 \
  --server-ip-address 192.168.43.2
```

Here's an example issuing a single request and receiving a 10 MiB response:

```bash
cargo run --release -- \
  --quinn-config test-data/earth-mars/quinn.json \
  --network-graph test-data/earth-mars/networkgraph-5nodes.json \
  --network-events test-data/earth-mars/events.json \
  --client-ip-address 192.168.40.1 \
  --server-ip-address 192.168.43.2 \
  --requests 1 --response-size 10485760
```

Here's an example controlling the random seeds (which otherwise use a hardcoded constant):

```bash
cargo run --release -- \
  --quinn-config test-data/earth-mars/quinn.json \
  --network-graph test-data/earth-mars/networkgraph-5nodes.json \
  --network-events test-data/earth-mars/events.json \
  --client-ip-address 192.168.40.1 \
  --server-ip-address 192.168.43.2 \
  --quinn-rng-seed 1234 --simulated-network-rng-seed 1337
```

Here's an example using random seeds derived from a source of entropy:

```bash
cargo run --release -- \
  --quinn-config test-data/earth-mars/quinn.json \
  --network-graph test-data/earth-mars/networkgraph-5nodes.json \
  --network-events test-data/earth-mars/events.json \
  --client-ip-address 192.168.40.1 \
  --server-ip-address 192.168.43.2 \
  --non-deterministic
```

## JSON config details

#### Quinn config

Consider the following quinn config (which gets loaded through the `--quinn-config` flag, as shown
in the previous examples):

```json
{
  "initial_rtt_ms": 100000000,
  "maximum_idle_timeout_ms": 100000000000,
  "packet_threshold": 4294967295,
  "mtu_discovery": false,
  "maximize_send_and_receive_windows": true,
  "max_ack_delay_ms": 18446744073709551615,
  "ack_eliciting_threshold": 10,
  "fixed_congestion_window": 10240
}
```

Here's the meaning of the different parameters:

- `initial_rtt_ms`: The initial Round Trip Time (RTT) of the QUIC connection in milliseconds
  (used before an actual RTT sample is available). For delay-tolerant networking, set this slightly
  higher than the expected real RTT to avoid unnecessary packet retransmissions.
- `maximum_idle_timeout_ms`: The maximum idle timeout of the QUIC connection in milliseconds.
  For continuous information exchange, use a small value to detect connection loss quickly. For
  delay-tolerant networking, use a very high value to prevent connection loss due to unexpected
  delays.
- `packet_threshold`: Maximum reordering in packet numbers before considering a packet lost.
  Should not be less than 3, as per RFC5681.
- `mtu_discovery`: Boolean flag to enable or disable MTU discovery.
- `maximize_send_and_receive_windows`: Boolean flag to maximize send and receive windows,
  allowing an unlimited number of unacknowledged in-flight packets.
- `max_ack_delay_ms`: The maximum amount of time, in milliseconds, that an endpoint waits
  before sending an ACK when the ACK-eliciting threshold hasn't been reached. Setting this to a high
  value is useful in combination with a high ACK-eliciting threshold.
- `ack_eliciting_threshold`: The number of ACK-eliciting packets an endpoint may receive
  without immediately sending an ACK. A high value is useful when expecting long streams of
  information from the server without sending anything back from the client.
- `fixed_congestion_window` (optional): If provided, disables congestion control and uses a
  fixed congestion window size in bytes.

#### Network topology config

The topology configuration is fairly self-documenting. See for instance
[networkgraph-fullmars.json](test-data/earth-mars/networkgraph-fullmars.json) and
[networkgraph-5nodes.json](test-data/earth-mars/networkgraph-5nodes.json)

Note that links are uni-directional, so two entries are necessary to describe a bidirectional link.
Also, links can be configured individually with the following parameters:

- `link.delay_ms` (required): The delay of the link in milliseconds (i.e. time it takes for a packet
  to arrive to its destination).
- `link.bandwidth_bps` (required): The bandwidth of the link in bits per second.
- `link.extra_delay_ms`: The additional delay of the link in milliseconds, applied randomly
  according to `extra_delay_ratio`.
- `link.extra_delay_ratio`: The ratio of packets that will have an extra delay applied, used to
  artificially introduce packet reordering (the value must be between 0 and 1).
- `link.packet_duplication_ratio`: The ratio of packets that will be duplicated upon being sent,
  (the value must be between 0 and 1).
- `link.packet_loss_ratio`: The ratio of packets that will be lost during transmission (the value
  must be between 0 and 1).
- `link.congestion_event_ratio`: The ratio of packets that will be marked with a CE ECN codepoint
  (the value must be between 0 and 1).

#### Network events config

Network events are used to bring links up and down at different times of the simulation (e.g. to
simulate an orbiter being unreachable at specific intervals). The format is fairly self-documenting,
as you can see in [events.json](test-data/earth-mars/events.json).

## Command line arguments

While the JSON configuration controls the QUIC and network parameters, the following command line
flags control other aspects of the simulation:

```
--client-ip-address <CLIENT_IP_ADDRESS>
    The IP address of the node used as a client

--server-ip-address <SERVER_IP_ADDRESS>
    The IP address of the node used as a server

--requests <REQUESTS>
    The number of requests that should be made

    [default: 10]

--concurrent-connections <CONCURRENT_CONNECTIONS>
    The number of concurrent connections used when making the requests

    [default: 1]

--concurrent-streams-per-connection <CONCURRENT_STREAMS_PER_CONNECTION>
    The number of concurrent streams per connection used when making the requests

    [default: 1]

--response-size <RESPONSE_SIZE>
    The size of each response, in bytes

    [default: 1024]

--non-deterministic
    Whether the run should be non-deterministic, i.e. using a non-constant seed for the random number generators

--quinn-rng-seed <QUINN_RNG_SEED>
    Quinn's random seed, which you can control to generate deterministic results (Quinn uses randomness internally)

    [default: 0]

--simulated-network-rng-seed <SIMULATED_NETWORK_RNG_SEED>
    The random seed used for the simulated network (governing packet loss, duplication and reordering)

    [default: 42]

--network-graph <NETWORK_GRAPH_JSON_FILE>
    Creates a network based on the topology described in the JSON file

--network-events <NETWORK_EVENTS_JSON_FILE>
    Apply various timed events, such as link up and down, to the network

```

### Acknowledgements

With special thanks to Marc Blanchet ([Viagénie inc.](https://www.viagenie.ca/)) for funding this
work.
