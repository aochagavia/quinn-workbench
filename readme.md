Deep Space Quinn Workbench
==========================

A command-line application to simulate QUIC connections in different scenarios (network
characteristics and QUIC parameters). The simulation creates a single connection, issues a fixed
number of requests from the client to the server, and streams the server's responses back to the
client.

### Features

- Pure. No IO operations are made, everything happens in-memory within a single process.
- Time warping. The simulation's internal clock advances automatically to the next event, making the
  simulation complete in an instant (even in the presence of deep-space-like RTTs).
- Deterministic. Two runs with the same parameters yield the same output.
- Inspectable. Next to informative command-line output and statistics, the application generates a
  synthetic pcap file, so you can examine the traffic in more detail using Wireshark.
- Configurable network settings and QUIC parameters through reusable JSON config files (see
  `example-configs` and [JSON config details](#json-config-details)).
- Configurable simulation behavior through command-line arguments (see `cargo run --release --
  --help`).

### Getting started

After [installing Rust](https://rustup.rs/), you can get started with:

```bash
cargo run --release -- --config example-configs/dtn.json
```

Here's an example issuing a single request and receiving a 10 MiB response:

```bash
cargo run --release -- --config example-configs/terrestrial-internet.json --repeat 1 --response-size 10485760
```

Here's an example controlling the random seeds (which otherwise use a hardcoded constant):

```bash
cargo run --release -- --config example-configs/terrestrial-internet.json --quinn-rng-seed 1234 --simulated-network-rng-seed 1337
```

Here's an example using random seeds derived from a source of entropy:

```bash
cargo run --release -- --config example-configs/terrestrial-internet.json --non-deterministic
```

### JSON config details

Consider the following config:

```json
{
  "quinn": {
    "initial_rtt_ms": 100000000,
    "maximum_idle_timeout_ms": 100000000000,
    "packet_threshold": 4294967295,
    "mtu_discovery": false,
    "maximize_send_and_receive_windows": true,
    "max_ack_delay_ms": 18446744073709551615,
    "ack_eliciting_threshold": 10,
    "fixed_congestion_window": 10240
  },
  "network": {
    "delay_ms": 5000,
    "extra_delay_ms": 200,
    "extra_delay_ratio": 0.1,
    "packet_duplication_ratio": 0.05,
    "packet_loss_ratio": 0.05,
    "bandwidth": 10240
  }
}
```

Here's the meaning of the different parameters:

- `quinn.initial_rtt_ms`: The initial Round Trip Time (RTT) of the QUIC connection in milliseconds
  (used before an actual RTT sample is available). For delay-tolerant networking, set this slightly
  higher than the expected real RTT to avoid unnecessary packet retransmissions.
- `quinn.maximum_idle_timeout_ms`: The maximum idle timeout of the QUIC connection in milliseconds.
  For continuous information exchange, use a small value to detect connection loss quickly. For
  delay-tolerant networking, use a very high value to prevent connection loss due to unexpected
  delays.
- `quinn.packet_threshold`: Maximum reordering in packet numbers before considering a packet lost.
  Should not be less than 3, as per RFC5681.
- `quinn.mtu_discovery`: Boolean flag to enable or disable MTU discovery.
- `quinn.maximize_send_and_receive_windows`: Boolean flag to maximize send and receive windows,
  allowing an unlimited number of unacknowledged in-flight packets.
- `quinn.max_ack_delay_ms`: The maximum amount of time, in milliseconds, that an endpoint waits
  before sending an ACK when the ACK-eliciting threshold hasn't been reached. Setting this to a high
  value is useful in combination with a high ACK-eliciting threshold.
- `quinn.ack_eliciting_threshold`: The number of ACK-eliciting packets an endpoint may receive
  without immediately sending an ACK. A high value is useful when expecting long streams of
  information from the server without sending anything back from the client.
- `quinn.fixed_congestion_window` (optional): If provided, disables congestion control and uses a
  fixed congestion window size in bytes.
- `network.delay_ms`: The one-way delay of the network in milliseconds.
- `network.extra_delay_ms`: The additional one-way delay of the network in milliseconds, applied
  randomly according to `extra_delay_ratio`.
- `network.extra_delay_ratio`: The ratio of packets that will have an extra delay applied,
  simulating packet reordering (the value must be between 0 and 1).
- `network.packet_duplication_ratio`: The ratio of packets that will be duplicated upon being sent
  (the value must be between 0 and 1).
- `network.packet_loss_ratio`: The ratio of packets that will be lost during transmission (the value
  must be between 0 and 1).
- `network.bandwidth`: The one-way bandwidth of the network in bytes.

### Command line arguments

While the JSON configuration controls the QUIC and network parameters, the following command line
flags control other aspects of the simulation:

```
--repeat <REPEAT>
    The amount of times the request should be repeated
    
    [default: 10]

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

```

### Acknowledgements

With special thanks to Marc Blanchet ([Viagénie inc.](https://www.viagenie.ca/)) for funding this
work.
