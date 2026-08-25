use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::{fmt, io, time};

use crate::config::Config;
use crate::unversioned::transport::time::Instant;
use crate::util::IoResultExt;
use crate::{Error, Timeout};

use super::ResolvedSocketAddrs;
use super::chain::Either;

use super::time::Duration;
use super::{Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport};

/// Connector for regular TCP sockets.
#[derive(Default)]
pub struct TcpConnector {
    local_ip: Option<IpAddr>,
}

impl TcpConnector {
    /// Bind outgoing TCP sockets to this local IP before connecting.
    pub fn with_local_ip(local_ip: IpAddr) -> Self {
        Self {
            local_ip: Some(local_ip),
        }
    }
}

impl<In: Transport> Connector<In> for TcpConnector {
    type Out = Either<In, TcpTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, Error> {
        if chained.is_some() {
            // The chained connection overrides whatever we were to open here.
            // In the DefaultConnector chain this would be a SOCKS proxy connection.
            trace!("Skip");
            return Ok(chained.map(Either::A));
        }

        let config = &details.config;
        let stream = try_connect(
            &details.addrs,
            details.now,
            details.timeout,
            details.current_time.clone(),
            config,
            self.local_ip,
        )?;

        let buffers = LazyBuffers::new(config.input_buffer_size(), config.output_buffer_size());
        let transport = TcpTransport::new(stream, buffers);

        Ok(Some(Either::B(transport)))
    }
}

fn try_connect(
    addrs: &ResolvedSocketAddrs,
    start: Instant,
    timeout: NextTimeout,
    current_time: Arc<dyn Fn() -> Instant + Send + Sync + 'static>,
    config: &Config,
    local_ip: Option<IpAddr>,
) -> Result<TcpStream, Error> {
    // The idea here is to give each attempt a budget of the total time to try.
    // For a host returning multiple addresses, we share the budget between them
    // using a geometric series that sums to exactly the total budget.
    //
    // Background: https://curl.se/mail/lib-2021-01/0037.html
    //
    // Example: Timeout is 10 seconds, and the host returns 4 addresses.
    //
    // Address 0: 5.33 seconds (53.3% of budget)
    // Address 1: 2.67 seconds (26.7% of budget)
    // Address 2: 1.33 seconds (13.3% of budget)
    // Address 3: 0.67 seconds (6.7% of budget)
    // Sum: 10.0 seconds
    //
    // For a single address, it gets the full budget (100%).
    // We cap the lowest to 10ms.
    //
    const MIN_PER_ADDRESS_TIMEOUT: Duration = Duration::from_millis(10);

    let num_addrs = addrs.len();

    // Pre-calculate the total weight for the geometric series.
    // For weights [1, 1/2, 1/4, 1/8, ...], the sum is 2 * (1 - 1/2^n)
    let total_weight = 2.0 * (1.0 - 0.5_f64.powi(num_addrs as i32));

    // Start with weight 1.0 for the first address, then halve for each subsequent.
    let mut weight = 1.0_f64;

    for addr in addrs {
        // Calculate this address's timeout using geometric series.
        let per_addr = timeout.not_zero().map(|t| {
            let secs = t.as_secs_f64() * weight / total_weight;
            let timeout = Duration::from_millis((secs * 1000.0) as u64);
            timeout.max(MIN_PER_ADDRESS_TIMEOUT)
        });

        match try_connect_single(*addr, per_addr, config, local_ip) {
            // First that connects
            Ok(v) => return Ok(v),
            // Intercept ConnectionRefused to try next addrs
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
                trace!("{} connection refused", addr);
                continue;
            }
            Err(Error::Timeout(_)) => {
                // Check if we hit the overall global timeout for the connect.
                let elapsed = current_time().duration_since(start);
                if elapsed > timeout.after {
                    return Err(Error::Timeout(timeout.reason));
                }

                // We still got time to try the next address.
            }
            // Other errors bail
            Err(e) => return Err(e),
        }

        // Halve the weight for the next address
        weight /= 2.0;
    }

    debug!("Failed to connect to any resolved address");
    Err(Error::Io(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "Connection refused",
    )))
}

fn try_connect_single(
    addr: SocketAddr,
    per_addr: Option<Duration>,
    config: &Config,
    local_ip: Option<IpAddr>,
) -> Result<TcpStream, Error> {
    trace!("Try connect TcpStream to {}", addr);

    let maybe_stream = connect_socket(addr, per_addr, local_ip).normalize_would_block();

    let stream = match maybe_stream {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            // The value passed here is ignored by the parent try_connect().
            return Err(Error::Timeout(Timeout::Connect));
        }
        Err(e) => return Err(e.into()),
    };

    if config.no_delay() {
        stream.set_nodelay(true)?;
    }

    debug!("Connected TcpStream to {}", addr);

    Ok(stream)
}

pub(super) fn connect_socket(
    addr: SocketAddr,
    timeout: Option<Duration>,
    local_ip: Option<IpAddr>,
) -> io::Result<TcpStream> {
    let Some(local_ip) = local_ip else {
        return if let Some(timeout) = timeout {
            TcpStream::connect_timeout(&addr, *timeout)
        } else {
            TcpStream::connect(addr)
        };
    };
    if local_ip.is_ipv4() != addr.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "local bind IP family does not match remote address",
        ));
    }
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.bind(&SocketAddr::new(local_ip, 0).into())?;
    if let Some(timeout) = timeout {
        socket.connect_timeout(&addr.into(), *timeout)?;
    } else {
        socket.connect(&addr.into())?;
    }
    Ok(socket.into())
}

pub struct TcpTransport {
    stream: TcpStream,
    buffers: LazyBuffers,
    timeout_write: Option<Duration>,
    timeout_read: Option<Duration>,
}

impl TcpTransport {
    pub fn new(stream: TcpStream, buffers: LazyBuffers) -> TcpTransport {
        TcpTransport {
            stream,
            buffers,
            timeout_read: None,
            timeout_write: None,
        }
    }
}

// The goal here is to only cause a syscall to set the timeout if it's necessary.
fn maybe_update_timeout(
    timeout: NextTimeout,
    previous: &mut Option<Duration>,
    stream: &TcpStream,
    f: impl Fn(&TcpStream, Option<time::Duration>) -> io::Result<()>,
) -> io::Result<()> {
    let maybe_timeout = timeout.not_zero();

    if maybe_timeout != *previous {
        (f)(stream, maybe_timeout.map(|t| *t))?;
        *previous = maybe_timeout;
    }

    Ok(())
}

impl Transport for TcpTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
        maybe_update_timeout(
            timeout,
            &mut self.timeout_write,
            &self.stream,
            TcpStream::set_write_timeout,
        )?;

        let output = &self.buffers.output()[..amount];
        match self.stream.write_all(output).normalize_would_block() {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(Error::Timeout(timeout.reason)),
            Err(e) => Err(e.into()),
        }?;

        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
        // Proceed to fill the buffers from the TcpStream
        maybe_update_timeout(
            timeout,
            &mut self.timeout_read,
            &self.stream,
            TcpStream::set_read_timeout,
        )?;

        let input = self.buffers.input_append_buf();
        let amount = match self.stream.read(input).normalize_would_block() {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(Error::Timeout(timeout.reason)),
            Err(e) => Err(e.into()),
        }?;
        self.buffers.input_appended(amount);

        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        probe_tcp_stream(&mut self.stream).unwrap_or(false)
    }

    fn try_clone_tcp_stream(&self) -> io::Result<Option<TcpStream>> {
        self.stream.try_clone().map(Some)
    }
}

fn probe_tcp_stream(stream: &mut TcpStream) -> Result<bool, Error> {
    // Temporary do non-blocking IO
    stream.set_nonblocking(true)?;

    let mut buf = [0];
    match stream.read(&mut buf) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            // This is the correct condition. There should be no waiting
            // bytes, and therefore reading would block
        }
        // Any bytes read means the server sent some garbage we didn't ask for
        Ok(_) => {
            debug!("Unexpected bytes from server. Closing connection");
            return Ok(false);
        }
        // Errors such as closed connection
        Err(_) => return Ok(false),
    };

    // Reset back to blocking
    stream.set_nonblocking(false)?;

    Ok(true)
}

impl fmt::Debug for TcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnector").finish()
    }
}

impl fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpTransport")
            .field("addr", &self.stream.peer_addr().ok())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::{LazyBuffers, TcpTransport, Transport, connect_socket};

    #[test]
    fn readiness_stream_is_a_clone_of_the_transport_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let transport = TcpTransport::new(client, LazyBuffers::new(1024, 1024));

        let readiness = transport
            .try_clone_tcp_stream()
            .unwrap()
            .expect("TCP transport has a readiness socket");

        assert_eq!(
            readiness.peer_addr().unwrap(),
            transport.stream.peer_addr().unwrap()
        );
    }

    #[test]
    fn connector_can_bind_a_local_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = connect_socket(
            listener.local_addr().unwrap(),
            Some(std::time::Duration::from_secs(1).into()),
            Some("127.0.0.1".parse().unwrap()),
        )
        .unwrap();
        let (server, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        drop((client, server));
    }
}
