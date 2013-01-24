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

## Todo

* Provide a mechanism to enable backends to exchange data with its
  counterpart, so that more complicated backends can be implemented.
