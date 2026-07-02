//! WebSocket transport for the Nostr relay pool routed through the
//! in-process smolmix tunnel (ported from `goblin/src/nym/transport.rs`), so
//! every relay connection traverses the 5-hop Nym mixnet. The relay host is
//! resolved through the tunnel (mix-dns — the destination is never resolved
//! on the clear), the TCP stream is opened via `tunnel.tcp_connect`, then the
//! TLS (rustls, webpki roots) + websocket handshake runs over that tunneled
//! stream. Nothing goes clearnet.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_wsocket::futures_util::{Sink, SinkExt, StreamExt};
use async_wsocket::{ConnectionMode, Message};
use nostr_relay_pool::transport::error::TransportError;
use nostr_relay_pool::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use nostr_sdk::util::BoxedFuture;
use nostr_sdk::Url;
use tokio_tungstenite::tungstenite::Message as TgMessage;

/// Error type for transport failures outside the websocket layer.
#[derive(Debug)]
struct NymTransportError(String);

impl fmt::Display for NymTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for NymTransportError {}

fn terr(msg: impl Into<String>) -> TransportError {
    TransportError::backend(NymTransportError(msg.into()))
}

/// Nostr websocket transport over the in-process Nym mixnet tunnel.
#[derive(Debug, Clone, Copy, Default)]
pub struct NymWebSocketTransport;

impl WebSocketTransport for NymWebSocketTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        _mode: &'a ConnectionMode,
        timeout: Duration,
    ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
        Box::pin(async move {
            let host = url
                .host_str()
                .ok_or_else(|| terr("relay url has no host"))?
                .to_string();
            let port = url.port().unwrap_or(match url.scheme() {
                "ws" => 80,
                _ => 443,
            });

            // The shared mixnet tunnel (lazy-started at server boot).
            let tunnel = super::nymproc::wait_for_tunnel(timeout)
                .await
                .ok_or_else(|| terr("nym tunnel not ready"))?;

            // Resolve the relay host through the mixnet (mix-dns), so no
            // clearnet DNS leak, then dial through the same tunnel.
            let addr = tokio::time::timeout(timeout, super::dns::resolve(&tunnel, &host, port))
                .await
                .map_err(|_| terr("mix-dns resolve timeout"))?
                .ok_or_else(|| terr(format!("mix-dns could not resolve relay host {host}")))?;
            let stream = tokio::time::timeout(timeout, tunnel.tcp_connect(addr))
                .await
                .map_err(|_| terr("nym tunnel connect timeout"))?
                .map_err(|e| terr(format!("nym tunnel connect failed: {e}")))?;

            // Perform TLS (for wss) + websocket handshake over the mixnet
            // stream (rustls webpki roots; the ring provider is installed
            // once at gp-server startup — the Build 65/66 rule).
            let (ws, _response) = tokio::time::timeout(
                timeout,
                tokio_tungstenite::client_async_tls(url.as_str(), stream),
            )
            .await
            .map_err(|_| terr("websocket handshake timeout"))?
            .map_err(|e| terr(format!("websocket handshake failed: {e}")))?;

            let (tx, rx) = ws.split();

            let sink: WebSocketSink = Box::new(NymSink(tx)) as WebSocketSink;
            let stream: WebSocketStream = Box::pin(rx.filter_map(|msg| async move {
                match msg {
                    Ok(tg) => tg_to_message(tg).map(Ok),
                    Err(e) => Some(Err(TransportError::backend(e))),
                }
            })) as WebSocketStream;

            Ok((sink, stream))
        })
    }
}

/// Convert a tungstenite message into an async-wsocket pool message.
/// Returns `None` for raw frames (never surfaced while reading).
fn tg_to_message(msg: TgMessage) -> Option<Message> {
    match msg {
        TgMessage::Text(text) => Some(Message::Text(text.to_string())),
        TgMessage::Binary(data) => Some(Message::Binary(data.to_vec())),
        TgMessage::Ping(data) => Some(Message::Ping(data.to_vec())),
        TgMessage::Pong(data) => Some(Message::Pong(data.to_vec())),
        TgMessage::Close(_) => Some(Message::Close(None)),
        TgMessage::Frame(_) => None,
    }
}

/// Sink adapter converting pool messages into tungstenite messages.
struct NymSink<S>(S);

impl<S> Sink<Message> for NymSink<S>
where
    S: Sink<TgMessage, Error = tokio_tungstenite::tungstenite::Error> + Send + Unpin,
{
    type Error = TransportError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_ready_unpin(cx)
            .map_err(TransportError::backend)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send_unpin(TgMessage::from(item))
            .map_err(TransportError::backend)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush_unpin(cx)
            .map_err(TransportError::backend)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close_unpin(cx)
            .map_err(TransportError::backend)
    }
}
