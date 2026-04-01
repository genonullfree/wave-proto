# Wave Protocol

Wave is a simple protocol that runs over UDP and adds a layer of encryption
using ECDH to transfer an AES256GCM key for transparent security. This is a
simple and relatively safe way to quickly add a layer of encryption to any
hobby project.

## Configuration and Use

The beauty of Wave is that there is no configuration. The protocol handles
all encryption natively and transparently so you can get to the fun part of
network programming.

To add Wave to your rust project, simply do:
```bash
cargo add wave-proto
```

Then in your project files, import the following as necessary:
```bash
use wave-proto::Wave;
```

The Wave object is used to handle all the networking and encryption. This
object is instantiated in the following ways:
```bash
let w = Wave::new();            // This binds to a local ephemeral port
let w = Wave::listen();         // This binds to the Wave standard local port 9003
let w = Wave::listen_on(####);  // This binds to a user-defined port ####
```

Once instantiated, Wave can then "connect" to a remote network device
("connect" in quotes as this is over UDP). Encryption is established during
this connection phase.
```bash
// The connect function takes in an IP and port as a &str, and returns a
// SocketAddr for the connection to the remote host.
let remoteSA = w.connect("X.X.X.X:####").await?;
```

This SocketAddr is used for some of the communication management. It is
currently due to how the Wave instance can handle encryption and communication
with multiple remote hosts simultaneously, if desired.

The initial transparent connection traffic flow and key exchange is like this:
```
client generates ECDH private + public values
client sends public value to server ---> server receives public value and generates
                                            it's own private + public values
                                    <--- server calculates the shared secret and
                                            sends its public value to the client
client receives the public value         server applies the shared secret as the
and calculates the shared secret            encryption key

client applies shared secret as
the encryption key

client generates an AES256 key      ---> server receives the AES256 key, decrypts it
and sends it encrypted with the             and applies it as the encryption key
shared secret to the server

client applies the AES256 key
as the encryption key
```

## Sending and Receiving

Once the connection is established, sending and receiving messages is now
relatively simple.
```bash
let sent_bytes = w.send(&remoteSA, data.as_bytes()).await?;
...
let (_remoteSA, message) = w.receive().await?;
```

## Message Queues

Wave also has simple message queuing capabilities. Instead of using `.send()`,
you need to use `.queue_send()`:
```bash
let sent_bytes_vec = w.queue_send(&remoteSA, data.as_bytes()).await?;
```
When this is used, Wave will check to see if the queue is empty or if it needs
to send the queue data first, and then the new message. If the queue is empty
and the send fails, the message is added to an internal Wave queue which will
then be attempted to be sent during the next call to `.queue_send()`. Queues
can be reset by calling `.queue_clear()`. The queue is convenient for use when
the remote host may not always be up. The messages in the queue will be sent
oldest first (FIFO). This function returns a vector of sent message length
values.


**DISCLAIMER**
This protocol has not been audited nor designed for top-tier security and
safety. It was designed with basic encryption principles in mind but does not
cover all edge cases and is likely flawed. See license file for more details,
but basically: use at your own risk.
