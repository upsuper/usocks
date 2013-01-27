# usocks

usocks is a protocol and a corresponding implementation designed to
provides an almost absolutely secure tunnel for data transmission to
protect data against not only the basic kinds of attacks but also
protocol-detection attack and even traffic analysis.

Preshared key is used to encrypt all data transmitted between client
and server, hence no protocol feature (except traffic feature) is
exposed to a third party. Protocol has also provided a mechanism to
defend against traffic analysis, but it has not been implemented at
present.

It is possible to extend usocks by implementing more complex backends
(for example, transmits data via more than one connections) to puzzle
analyser, and possibly improve the performance.

## Design

usocks is divided into four layers, which are backend, record layer,
tunnel layer, and frontend, from lower to upper. The function of
record and tunnel layer should be identical among implementations,
while backend need to be compatible with the counterpart. Frontend
exists only in server side.

A backend must provide reliablity and ordering for its upper layer,
record layer. Currently, there is only a simple backend which uses
TCP directly.

Record layer is the key to secure data in the whole protocol. Data
encryption and verification is done here, and all data is transmitted
via the same connection in this layer. Details about protocol of
record layer can be found in `src/record.py`.

There is two halves of tunnel layer: one is in client side and the
other is in server side. Client half of tunnel layer collects ouside
connections, packs/unpacks data and exchanges it with record layer.
Server half does something similar: it passes data between record
layer and frontend. More details are in `src/tunnel.py`.

Frontend is what actually serves the outside client (which connects
to the client of usocks). Connections linked to usocks client can
be virtually regarded as being linked to the frontend. At present,
the implementation only includes the simplest frontend which redirects
connections to a given network address.

## Requirement

usocks, the implementation, requires Python 2.6.x or 2.7.x with the
following packages:

* [pycrypto](https://www.dlitz.net/software/pycrypto/)
* [PyYAML](http://pyyaml.org/)

These two packages can be installed via `easy_install` or `pip`.

## Usage

### Configuration

You need to rename `src/config.sample.yaml` to `src/config.yaml` and
modify the options first for any usage. There are two main parts of
the config file: `client` and `server`. Putting them together enables
the config file to be shared among two sides. Generally speaking, the
only four fields you need to change are `client/backend/server`,
`client/backend/port`, `client/key`, and `client/port`. Follow the
comments to adjust it.

### Use as Proxy

Since there is no SOCKS server implementation included in usocks, you
have to setup an independent proxy server first,
such as [Dante](http://www.inet.no/dante/).

When the SOCKS server has been configured properly, you should set
`server/frontend/port` to the port it listens, so that usocks is able
to redirect traffic to the SOCKS server.

Finally execute `./server.py` on server, `./client.py` on client, and
setup applications to use the port as SOCKS server.

## Todo

* Provide a mechanism to enable backends to exchange data with its
  counterpart, so that more complicated backends can be implemented.
* Implement a simple SOCKSv5 server as a frontend.
