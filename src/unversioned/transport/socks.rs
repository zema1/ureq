use std::fmt;
use std::io::{Read, Write};
use std::iter::once;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::{io, thread};

use socks::{Socks4Stream, Socks5Stream, TargetAddr, ToTargetAddr};

use crate::Error;
use crate::proxy::{Proxy, ProxyProtocol};
use crate::util::UriExt;

use super::ResolvedSocketAddrs;
use super::chain::Either;

use super::tcp::TcpTransport;
use super::{ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport};

/// Connector for SOCKS proxies.
///
/// Requires the **socks-proxy** feature.
///
/// The connector looks at the proxy settings in [`proxy`](crate::config::ConfigBuilder::proxy) to
/// determine whether to attempt a proxy connection or not.
#[derive(Default)]
pub struct SocksConnector {
    local_ip: Option<IpAddr>,
}

impl SocksConnector {
    /// Bind the TCP connection to the SOCKS proxy to this local IP.
    pub fn with_local_ip(local_ip: IpAddr) -> Self {
        Self {
            local_ip: Some(local_ip),
        }
    }
}

impl<In: Transport> Connector<In> for SocksConnector {
    type Out = Either<In, TcpTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, Error> {
        let proxy = match details.config.proxy() {
            Some(v) if v.protocol().is_socks() => v,
            // If there is no proxy configured, or it isn't a SOCKS proxy, use whatever is chained.
            _ => {
                trace!("SOCKS not configured");
                return Ok(chained.map(Either::A));
            }
        };

        if chained.is_some() {
            trace!("Skip");
            return Ok(chained.map(Either::A));
        }

        let proxy_addrs = details
            .resolver
            .resolve(proxy.uri(), details.config, details.timeout)?;

        // Check if this host is not supposed to be proxied.
        let is_no_proxy = details
            .config
            .proxy()
            .map(|p| p.is_no_proxy(details.uri))
            .unwrap_or(false);

        if is_no_proxy {
            return Ok(None);
        }

        let stream = if proxy.resolve_target() {
            // The target is already resolved by run().
            let resolved = details.addrs.iter().cloned();

            try_connect(
                &proxy_addrs,
                resolved,
                proxy,
                details.timeout,
                self.local_ip,
            )?
        } else {
            // Do not to resolve the target locally, instead pass (host, port)
            // to the proxy and let it resolve.
            let iter = once(details.uri.host_port());
            try_connect(&proxy_addrs, iter, proxy, details.timeout, self.local_ip)?
        };

        if details.config.no_delay() {
            stream.set_nodelay(true)?;
        }

        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        let transport = TcpTransport::new(stream, buffers);

        Ok(Some(Either::B(transport)))
    }
}

fn try_connect<'a, T: ToTargetAddr + fmt::Debug + Send + 'a + Clone>(
    proxy_addrs: &ResolvedSocketAddrs,
    target_addrs: impl Iterator<Item = T>,
    proxy: &Proxy,
    timeout: NextTimeout,
    local_ip: Option<IpAddr>,
) -> Result<TcpStream, Error> {
    if !proxy_addrs
        .iter()
        .any(|addr| super::tcp::matches_local_ip_family(addr, local_ip))
    {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no resolved proxy address matches the local bind IP family",
        )));
    }

    for target_addr in target_addrs {
        for proxy_addr in proxy_addrs
            .iter()
            .filter(|addr| super::tcp::matches_local_ip_family(addr, local_ip))
        {
            trace!(
                "Try connect {} {} -> {:?}",
                proxy.protocol(),
                proxy_addr,
                target_addr
            );

            match try_connect_single(*proxy_addr, target_addr.clone(), proxy, timeout, local_ip) {
                Ok(v) => {
                    debug!(
                        "{} connected {} -> {:?}",
                        proxy.protocol(),
                        proxy_addr,
                        target_addr
                    );
                    return Ok(v);
                }
                // Intercept ConnectionRefused to try next addrs
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    trace!(
                        "{} -> {:?} proxy connection refused",
                        proxy_addr, target_addr
                    );
                    continue;
                }
                // Other errors bail
                Err(e) => return Err(e),
            }
        }
    }

    debug!("Proxy failed to to connect to any resolved address");
    Err(Error::Io(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "Connection refused",
    )))
}

fn try_connect_single<'a, T: ToTargetAddr + Send + 'a>(
    proxy_addr: SocketAddr,
    target_addr: T,
    proxy: &Proxy,
    timeout: NextTimeout,
    local_ip: Option<IpAddr>,
) -> Result<TcpStream, Error> {
    // The async behavior is only used if we want to time cap connecting.
    let use_sync = timeout.after.is_not_happening();

    if use_sync {
        connect_proxy(proxy, proxy_addr, target_addr, local_ip, None)
    } else {
        let (tx, rx) = mpsc::sync_channel(1);
        let proxy = proxy.clone();

        thread::scope(move |s| {
            s.spawn(move || {
                tx.send(connect_proxy(
                    &proxy,
                    proxy_addr,
                    target_addr,
                    local_ip,
                    timeout.not_zero(),
                ))
            });

            match rx.recv_timeout(*timeout.after) {
                Ok(v) => v,
                Err(RecvTimeoutError::Timeout) => Err(Error::Timeout(timeout.reason)),
                Err(RecvTimeoutError::Disconnected) => unreachable!("mpsc sender gone"),
            }
        })
    }
}

fn connect_proxy<'a, T: ToTargetAddr + 'a>(
    proxy: &Proxy,
    proxy_addr: SocketAddr,
    target_addr: T,
    local_ip: Option<IpAddr>,
    timeout: Option<super::time::Duration>,
) -> Result<TcpStream, Error> {
    if let Some(local_ip) = local_ip {
        return connect_bound_proxy(proxy, proxy_addr, target_addr, local_ip, timeout);
    }
    let stream = match proxy.protocol() {
        ProxyProtocol::Socks4 | ProxyProtocol::Socks4A => {
            if proxy.username().is_some() {
                debug!("SOCKS4 does not support username/password");
            }

            Socks4Stream::connect(proxy_addr, target_addr, "")?.into_inner()
        }

        ProxyProtocol::Socks5 | ProxyProtocol::Socks5h => {
            if let Some(username) = proxy.username() {
                // Connect with authentication.
                let password = proxy.password().unwrap_or("");

                Socks5Stream::connect_with_password(proxy_addr, target_addr, username, password)?
            } else {
                Socks5Stream::connect(proxy_addr, target_addr)?
            }
            .into_inner()
        }

        _ => unreachable!(), // HTTP(s) proxies.
    };

    Ok(stream)
}

fn connect_bound_proxy<T: ToTargetAddr>(
    proxy: &Proxy,
    proxy_addr: SocketAddr,
    target_addr: T,
    local_ip: IpAddr,
    timeout: Option<super::time::Duration>,
) -> Result<TcpStream, Error> {
    let mut stream = super::tcp::connect_socket(proxy_addr, timeout, Some(local_ip))?;
    let socket_timeout = timeout.map(|duration| *duration);
    stream.set_read_timeout(socket_timeout)?;
    stream.set_write_timeout(socket_timeout)?;
    let target = target_addr.to_target_addr()?;

    match proxy.protocol() {
        ProxyProtocol::Socks4 | ProxyProtocol::Socks4A => {
            connect_socks4(&mut stream, &target)?;
        }
        ProxyProtocol::Socks5 | ProxyProtocol::Socks5h => {
            connect_socks5(&mut stream, &target, proxy.username(), proxy.password())?;
        }
        _ => unreachable!(),
    }
    Ok(stream)
}

fn connect_socks4(stream: &mut TcpStream, target: &TargetAddr) -> io::Result<()> {
    let mut request = vec![4, 1];
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            request.extend_from_slice(&addr.port().to_be_bytes());
            request.extend_from_slice(&addr.ip().octets());
            request.push(0);
        }
        TargetAddr::Ip(SocketAddr::V6(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS4 does not support IPv6",
            ));
        }
        TargetAddr::Domain(domain, port) => {
            request.extend_from_slice(&port.to_be_bytes());
            request.extend_from_slice(&[0, 0, 0, 1]);
            request.push(0);
            request.extend_from_slice(domain.as_bytes());
            request.push(0);
        }
    }
    stream.write_all(&request)?;
    let mut response = [0u8; 8];
    stream.read_exact(&mut response)?;
    if response[0] != 0 || response[1] != 90 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS4 proxy rejected CONNECT with status {}", response[1]),
        ));
    }
    Ok(())
}

fn connect_socks5(
    stream: &mut TcpStream,
    target: &TargetAddr,
    username: Option<&str>,
    password: Option<&str>,
) -> io::Result<()> {
    let greeting: &[u8] = if username.is_some() {
        &[5, 2, 2, 0]
    } else {
        &[5, 1, 0]
    };
    stream.write_all(greeting)?;
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected)?;
    if selected[0] != 5 || selected[1] == 0xff {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy rejected authentication methods",
        ));
    }
    if selected[1] == 2 {
        let username = username.unwrap_or("");
        let password = password.unwrap_or("");
        if username.is_empty()
            || username.len() > u8::MAX as usize
            || password.is_empty()
            || password.len() > u8::MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SOCKS5 username or password length",
            ));
        }
        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.extend_from_slice(&[1, username.len() as u8]);
        auth.extend_from_slice(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        stream.write_all(&auth)?;
        let mut auth_response = [0u8; 2];
        stream.read_exact(&mut auth_response)?;
        if auth_response != [1, 0] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 password authentication failed",
            ));
        }
    } else if selected[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 proxy selected an unsupported authentication method",
        ));
    }

    let mut request = vec![5, 1, 0];
    encode_socks5_addr(&mut request, target)?;
    stream.write_all(&request)?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response)?;
    if response[0] != 5 || response[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 CONNECT response",
        ));
    }
    if response[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 proxy rejected CONNECT with status {}", response[1]),
        ));
    }
    consume_socks5_addr(stream, response[3])?;
    Ok(())
}

fn encode_socks5_addr(out: &mut Vec<u8>, target: &TargetAddr) -> io::Result<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(1);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 target domain is too long",
                ));
            }
            out.extend_from_slice(&[3, domain.len() as u8]);
            out.extend_from_slice(domain.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn consume_socks5_addr(stream: &mut TcpStream, addr_type: u8) -> io::Result<()> {
    let address_len = match addr_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 response address type",
            ));
        }
    };
    let mut remainder = vec![0u8; address_len + 2];
    stream.read_exact(&mut remainder)
}

impl fmt::Debug for SocksConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksConnector").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    fn spawn_socks5_server(listener: TcpListener) -> thread::JoinHandle<IpAddr> {
        thread::spawn(move || {
            let (mut socket, peer) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).unwrap();

            let mut request = [0u8; 4];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(&request[..3], &[5, 1, 0]);
            match request[3] {
                1 => {
                    let mut rest = [0u8; 6];
                    socket.read_exact(&mut rest).unwrap();
                }
                3 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).unwrap();
                    let mut rest = vec![0u8; len[0] as usize + 2];
                    socket.read_exact(&mut rest).unwrap();
                }
                4 => {
                    let mut rest = [0u8; 18];
                    socket.read_exact(&mut rest).unwrap();
                }
                value => panic!("unexpected address type {value}"),
            }
            socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            peer.ip()
        })
    }

    #[test]
    fn socks5_connection_can_bind_local_ip() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = spawn_socks5_server(listener);

        let proxy = Proxy::new(&format!("socks5://{proxy_addr}")).unwrap();
        let local_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let stream = connect_bound_proxy(
            &proxy,
            proxy_addr,
            "example.test:80",
            local_ip,
            Some(super::super::time::Duration::from_secs(2)),
        )
        .unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), local_ip);
        assert_eq!(server.join().unwrap(), local_ip);
    }

    #[test]
    fn local_ip_filters_proxy_addresses_but_not_target_addresses() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = spawn_socks5_server(listener);
        let proxy = Proxy::new(&format!("socks5://{proxy_addr}")).unwrap();
        let local_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let mut proxy_addrs = ResolvedSocketAddrs::from_fn(|_| proxy_addr);
        proxy_addrs.push(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            proxy_addr.port(),
        ));
        proxy_addrs.push(proxy_addr);

        let stream = try_connect(
            &proxy_addrs,
            once(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80)),
            &proxy,
            NextTimeout {
                after: super::super::time::Duration::from_secs(2),
                reason: crate::Timeout::Connect,
            },
            Some(local_ip),
        )
        .unwrap();

        assert_eq!(stream.local_addr().unwrap().ip(), local_ip);
        assert_eq!(server.join().unwrap(), local_ip);
    }
}
