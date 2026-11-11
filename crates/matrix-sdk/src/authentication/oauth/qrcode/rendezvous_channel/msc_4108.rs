// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{future::Future, time::Duration};

use http::{
    HeaderMap, HeaderName, Method, StatusCode,
    header::{CONTENT_TYPE, ETAG, EXPIRES, IF_MATCH, IF_NONE_MATCH, LAST_MODIFIED},
};
use matrix_sdk_base::sleep;
use matrix_sdk_common::timeout::timeout;
use ruma::{
    api::{
        EndpointError,
        error::{FromHttpResponseError, HeaderDeserializationError, IntoHttpError},
    },
    http_headers::http_date_to_system_time,
    time::{Instant, SystemTime},
};
use tracing::{debug, instrument, trace};
use url::Url;

use crate::{HttpError, RumaApiError, http_client::HttpClient};

const TEXT_PLAIN_CONTENT_TYPE: &str = "text/plain";
// A server must not keep a login alive indefinitely by returning 304 or moving
// Expires into the future. Allow time for scanning, check-code entry and MFA.
const MAX_CHANNEL_LIFETIME: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const POLL_TIMEOUT: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const POLL_TIMEOUT: Duration = Duration::from_secs(1);

type Etag = String;

fn expiry_deadline(expires: SystemTime) -> Instant {
    Instant::now()
        + expires.duration_since(SystemTime::now()).unwrap_or_default().min(MAX_CHANNEL_LIFETIME)
}

fn shorten_deadline(deadline: &mut Instant, expires: &http::HeaderValue) -> Result<(), HttpError> {
    let expires = http_date_to_system_time(expires)
        .map_err(|error| Box::new(FromHttpResponseError::from(error)))?;
    *deadline = (*deadline).min(expiry_deadline(expires));
    Ok(())
}

/// Bound only rendezvous I/O, never OAuth requests that may issue credentials.
async fn before_deadline<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, HttpError>>,
) -> Result<T, HttpError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HttpError::RendezvousExpired);
    }
    let result = timeout(future, remaining).await.map_err(|_| HttpError::RendezvousExpired)?;
    // A ready future can win a timeout even when its timer has elapsed.
    if Instant::now() >= deadline {
        return Err(HttpError::RendezvousExpired);
    }
    result
}

/// Get a header from a [`HeaderMap`] and parse it as a UTF-8 string.
fn get_header(
    header_map: &HeaderMap,
    header_name: &HeaderName,
) -> Result<String, Box<FromHttpResponseError<RumaApiError>>> {
    let header = header_map
        .get(header_name)
        .ok_or(HeaderDeserializationError::MissingHeader(header_name.to_string()))
        .map_err(|error| Box::new(FromHttpResponseError::from(error)))?;

    let header =
        header.to_str().map_err(|error| Box::new(FromHttpResponseError::from(error)))?.to_owned();

    Ok(header)
}

fn response_to_error(status: StatusCode, body: &[u8]) -> HttpError {
    match http::Response::builder().status(status).body(body).map_err(IntoHttpError::from) {
        Ok(response) => {
            let error = FromHttpResponseError::<RumaApiError>::Server(RumaApiError::MatrixError(
                ruma::api::error::Error::from_http_response(response),
            ));

            error.into()
        }
        Err(e) => HttpError::IntoHttp(e),
    }
}

/// The result of the [`RendezvousChannel::create_inbound()`] method.
pub(super) struct InboundChannelCreationResult {
    /// The connected [`RendezvousChannel`].
    pub channel: Channel,
    /// The initial message we received when we connected to the
    /// [`RendezvousChannel`].
    ///
    /// This is currently unused, but left in for completeness sake.
    #[allow(dead_code)]
    pub initial_message: Vec<u8>,
}

pub(super) struct RendezvousGetResponse {
    pub status_code: StatusCode,
    pub etag: String,
    #[allow(dead_code)]
    pub last_modified: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

pub(super) struct RendezvousMessage {
    pub status_code: StatusCode,
    pub body: Vec<u8>,
    pub content_type: String,
}

pub struct Channel {
    client: HttpClient,
    rendezvous_url: Url,
    etag: Etag,
    /// Monotonic, non-extendable lifetime, also retained across receive calls.
    deadline: Instant,
}

impl Channel {
    /// Create a new outbound [`RendezvousChannel`].
    ///
    /// By outbound we mean that we're going to tell the Matrix server to create
    /// a new rendezvous session. We're going to send an initial empty message
    /// through the channel.
    pub(super) async fn create_outbound(
        client: HttpClient,
        rendezvous_server: &Url,
    ) -> Result<Self, HttpError> {
        use std::borrow::Cow;

        use ruma::api::{SupportedVersions, client::rendezvous::create_rendezvous_session};

        let request = create_rendezvous_session::unstable_msc4108::Request::default();
        let deadline = Instant::now() + MAX_CHANNEL_LIFETIME;
        let response = before_deadline(
            deadline,
            client.send(
                request,
                None,
                rendezvous_server.to_string(),
                None,
                Cow::Owned(SupportedVersions {
                    versions: Default::default(),
                    features: Default::default(),
                }),
                Default::default(),
            ),
        )
        .await?;

        let deadline = deadline.min(expiry_deadline(response.expires));
        if Instant::now() >= deadline {
            return Err(HttpError::RendezvousExpired);
        }

        let rendezvous_url = response.url;
        let etag = response.etag;

        Ok(Self { client, rendezvous_url, etag, deadline })
    }

    /// Create a new inbound [`RendezvousChannel`].
    ///
    /// By inbound we mean that we're going to attempt to read an initial
    /// message from the rendezvous session on the given [`rendezvous_url`].
    pub(super) async fn create_inbound(
        client: HttpClient,
        rendezvous_url: &Url,
    ) -> Result<InboundChannelCreationResult, HttpError> {
        // Receive the initial message, which should be empty. But we need the ETAG to
        // fully establish the rendezvous channel.
        let mut deadline = Instant::now() + MAX_CHANNEL_LIFETIME;
        let response =
            Self::receive_message_impl(&client.inner, None, rendezvous_url, &mut deadline).await?;

        let etag = response.etag.clone();

        let initial_message = RendezvousMessage {
            status_code: response.status_code,
            body: response.body,
            content_type: response.content_type.unwrap_or_else(|| "text/plain".to_owned()),
        };

        let channel = Self { client, rendezvous_url: rendezvous_url.clone(), etag, deadline };

        Ok(InboundChannelCreationResult { channel, initial_message: initial_message.body })
    }

    /// Get the URL of the rendezvous session we're using to exchange messages
    /// through the channel.
    pub(super) fn rendezvous_url(&self) -> &Url {
        &self.rendezvous_url
    }

    /// Send the given `message` through the [`RendezvousChannel`] to the other
    /// device.
    ///
    /// The message must be of the `text/plain` content type.
    #[instrument(skip_all)]
    pub(super) async fn send(&mut self, message: Vec<u8>) -> Result<(), HttpError> {
        let etag = self.etag.clone();

        let request = self
            .client
            .inner
            .request(Method::PUT, self.rendezvous_url().to_owned())
            .body(message)
            .header(IF_MATCH, etag)
            .header(CONTENT_TYPE, TEXT_PLAIN_CONTENT_TYPE);

        debug!("Sending a request to the rendezvous channel {request:?}");

        let response = before_deadline(self.deadline, async { Ok(request.send().await?) }).await?;
        let status = response.status();

        debug!("Response for the rendezvous sending request {response:?}");

        // Retain compatibility with servers omitting this header on PUT, while
        // honoring a shorter lifetime before accepting success or reading a body.
        if let Some(expires) = response.headers().get(EXPIRES) {
            shorten_deadline(&mut self.deadline, expires)?;
        }
        before_deadline(self.deadline, async {
            if status.is_success() {
                // We successfully sent a message; retain the new ETAG.
                self.etag = get_header(response.headers(), &ETAG)?;
                Ok(())
            } else {
                let body = response.bytes().await?;
                Err(response_to_error(status, &body))
            }
        })
        .await
    }

    /// Attempt to receive a message from the [`RendezvousChannel`] from the
    /// other device.
    ///
    /// The content should be of the `text/plain` content type but the parsing
    /// and verification of this fact is left up to the caller.
    ///
    /// This method will wait in a loop for the channel to give us a new
    /// message.
    pub(super) async fn receive(&mut self) -> Result<Vec<u8>, HttpError> {
        loop {
            let message = self.receive_single_message().await?;

            trace!(
                status_code = %message.status_code,
                "Received data from the rendezvous channel"
            );

            if message.status_code == StatusCode::OK
                && message.content_type == TEXT_PLAIN_CONTENT_TYPE
                && !message.body.is_empty()
            {
                return Ok(message.body);
            } else if message.status_code == StatusCode::NOT_MODIFIED {
                before_deadline(self.deadline, async {
                    sleep::sleep(POLL_TIMEOUT).await;
                    Ok(())
                })
                .await?;
                continue;
            } else {
                let error = response_to_error(message.status_code, &message.body);

                return Err(error);
            }
        }
    }

    #[instrument]
    async fn receive_message_impl(
        client: &reqwest::Client,
        etag: Option<String>,
        rendezvous_url: &Url,
        deadline: &mut Instant,
    ) -> Result<RendezvousGetResponse, HttpError> {
        let mut builder = client.request(Method::GET, rendezvous_url.to_owned());

        if let Some(etag) = etag {
            builder = builder.header(IF_NONE_MATCH, etag);
        }

        let response = before_deadline(*deadline, async { Ok(builder.send().await?) }).await?;

        debug!("Received data from the rendezvous channel {response:?}");

        let status_code = response.status();

        // Apply a shorter expiry before reading any body, including errors.
        // Error responses without common headers retain the existing deadline.
        let headers = response.headers();
        if let Some(expires) = headers.get(EXPIRES) {
            shorten_deadline(deadline, expires)?;
        } else if !status_code.is_client_error() {
            return Err(Box::new(FromHttpResponseError::from(
                HeaderDeserializationError::MissingHeader(EXPIRES.to_string()),
            ))
            .into());
        }

        if status_code.is_client_error() {
            let body = before_deadline(*deadline, async { Ok(response.bytes().await?) }).await?;
            return Err(response_to_error(status_code, &body));
        }

        let etag = get_header(headers, &ETAG)?;
        let last_modified = get_header(headers, &LAST_MODIFIED)?;
        #[allow(clippy::result_large_err)]
        let content_type = headers
            .get(CONTENT_TYPE)
            .map(|c| c.to_str().map_err(FromHttpResponseError::<RumaApiError>::from))
            .transpose()?
            .map(ToOwned::to_owned);

        let body =
            before_deadline(*deadline, async { Ok(response.bytes().await?.to_vec()) }).await?;

        let response =
            RendezvousGetResponse { status_code, etag, last_modified, content_type, body };

        Ok(response)
    }

    async fn receive_single_message(&mut self) -> Result<RendezvousMessage, HttpError> {
        let etag = Some(self.etag.clone());

        let RendezvousGetResponse { status_code, etag, content_type, body, .. } =
            Self::receive_message_impl(
                &self.client.inner,
                etag,
                &self.rendezvous_url,
                &mut self.deadline,
            )
            .await?;

        // We received a response with an ETAG, put it into the copy of our etag.
        self.etag = etag;

        let message = RendezvousMessage {
            status_code,
            body,
            content_type: content_type.unwrap_or_else(|| "text/plain".to_owned()),
        };

        Ok(message)
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod test {
    use matrix_sdk_test::async_test;
    use serde_json::json;
    use similar_asserts::assert_eq;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;
    use crate::config::RequestConfig;

    fn response(status: u16, expiry: SystemTime) -> ResponseTemplate {
        ResponseTemplate::new(status)
            .append_header("ETag", "1")
            .append_header("Content-Type", "text/plain")
            .append_header(
                "Expires",
                ruma::http_headers::system_time_to_http_date(&expiry).expect("valid expiry"),
            )
            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
    }

    async fn channel(server: &MockServer) -> Channel {
        let url = Url::parse(&server.uri()).expect("server URL");
        mock_rendzvous_create(server, &url.join("channel").expect("channel URL")).await;
        let client = HttpClient::new(reqwest::Client::new(), RequestConfig::new().disable_retry());
        Channel::create_outbound(client, &url).await.expect("outbound channel")
    }

    #[async_test]
    async fn test_repeated_304_cannot_extend_the_channel_lifetime() {
        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        // Shorten the production deadline so the regression need not take five minutes.
        channel.deadline = Instant::now() + Duration::from_millis(100);
        let deadline = channel.deadline;
        Mock::given(method("GET"))
            .respond_with(response(304, SystemTime::now() + Duration::from_secs(3600)))
            .expect(1..)
            .mount(&server)
            .await;

        let error = timeout(channel.receive(), Duration::from_secs(2))
            .await
            .expect("receive must terminate")
            .expect_err("expired channel");
        assert!(matches!(error, HttpError::RendezvousExpired));
        assert_eq!(channel.deadline, deadline);
        assert!(matches!(channel.receive().await, Err(HttpError::RendezvousExpired)));
        assert!(matches!(channel.send(vec![1]).await, Err(HttpError::RendezvousExpired)));
        assert!(channel.deadline <= Instant::now());
    }

    #[async_test]
    async fn test_receive_calls_share_the_original_deadline() {
        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        let deadline = channel.deadline;
        Mock::given(method("GET"))
            .respond_with(
                response(200, SystemTime::now() + Duration::from_secs(3600))
                    .set_body_string("message"),
            )
            .expect(2)
            .mount(&server)
            .await;
        assert_eq!(channel.receive().await.expect("first message"), b"message");
        assert_eq!(channel.receive().await.expect("second message"), b"message");
        assert_eq!(channel.deadline, deadline);
        assert!(deadline <= Instant::now() + MAX_CHANNEL_LIFETIME);
    }

    #[async_test]
    async fn test_expired_initial_responses_and_malformed_dates_fail_closed() {
        for expiry in ["Wed, 07 Sep 2022 14:28:51 GMT", "invalid-date"] {
            let server = MockServer::start().await;
            let url = Url::parse(&server.uri()).expect("server URL");
            for method_name in ["POST", "GET"] {
                Mock::given(method(method_name))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .append_header("ETag", "1")
                            .append_header("Expires", expiry)
                            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                            .set_body_json(json!({"url": url})),
                    )
                    .mount(&server)
                    .await;
            }
            let client =
                HttpClient::new(reqwest::Client::new(), RequestConfig::new().disable_retry());
            assert!(Channel::create_outbound(client.clone(), &url).await.is_err());
            assert!(Channel::create_inbound(client, &url).await.is_err());
        }
    }

    #[async_test]
    async fn test_earlier_expiry_rejects_even_a_successful_message() {
        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        Mock::given(method("GET"))
            .respond_with(
                response(200, SystemTime::now() - Duration::from_secs(60))
                    .set_body_string("too late"),
            )
            .mount(&server)
            .await;
        assert!(matches!(channel.receive().await, Err(HttpError::RendezvousExpired)));
    }

    #[async_test]
    async fn test_put_expiry_can_shorten_but_never_extend_the_channel() {
        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        let deadline = channel.deadline;
        let scope = Mock::given(method("PUT"))
            .respond_with(response(202, SystemTime::now() + Duration::from_secs(3600)))
            .mount_as_scoped(&server)
            .await;
        channel.send(vec![1]).await.expect("unexpired send");
        assert_eq!(channel.deadline, deadline);
        drop(scope);

        Mock::given(method("PUT"))
            .respond_with(response(202, SystemTime::now() - Duration::from_secs(60)))
            .mount(&server)
            .await;
        assert!(matches!(channel.send(vec![1]).await, Err(HttpError::RendezvousExpired)));
    }

    #[async_test]
    async fn test_put_accepts_missing_expiry_but_rejects_malformed_expiry() {
        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        let deadline = channel.deadline;
        let scope = Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(202).append_header("ETag", "2"))
            .mount_as_scoped(&server)
            .await;
        channel.send(vec![1]).await.expect("legacy response without expiry");
        assert_eq!(channel.deadline, deadline);
        drop(scope);

        Mock::given(method("PUT"))
            .respond_with(
                ResponseTemplate::new(202)
                    .append_header("ETag", "3")
                    .append_header("Expires", "invalid-date"),
            )
            .mount(&server)
            .await;
        assert!(channel.send(vec![1]).await.is_err());
        assert_eq!(channel.etag, "2", "malformed response was not accepted");
    }

    #[async_test]
    async fn test_stalled_rendezvous_requests_observe_the_same_deadline() {
        for method_name in ["GET", "PUT"] {
            let server = MockServer::start().await;
            let mut channel = channel(&server).await;
            channel.deadline = Instant::now() + Duration::from_millis(100);
            Mock::given(method(method_name))
                .respond_with(
                    response(200, SystemTime::now() + Duration::from_secs(60))
                        .set_body_string("late message")
                        .set_delay(Duration::from_secs(5)),
                )
                .mount(&server)
                .await;
            let operation = async {
                if method_name == "GET" {
                    channel.receive().await.map(|_| ())
                } else {
                    channel.send(vec![1]).await
                }
            };
            let error = timeout(operation, Duration::from_secs(2))
                .await
                .expect("bounded request")
                .expect_err("expired request");
            assert!(matches!(error, HttpError::RendezvousExpired));
        }
    }

    #[async_test]
    async fn test_stalled_body_uses_shorter_expiry_from_response_headers() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind body fixture");
        channel.rendezvous_url =
            Url::parse(&format!("http://{}/channel", listener.local_addr().expect("address")))
                .expect("URL");
        let stalled_body = async {
            let (mut socket, _) = listener.accept().await.expect("connection");
            let mut buf = [0_u8; 1024];
            assert!(socket.read(&mut buf).await.expect("request") > 0);
            let expiry = ruma::http_headers::system_time_to_http_date(
                &(SystemTime::now() + Duration::from_secs(2)),
            )
            .expect("expiry");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nETag: 1\r\nExpires: {}\r\nLast-Modified: Wed, 07 Sep 2022 14:27:51 GMT\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\n",
                expiry.to_str().expect("expiry text"),
            );
            socket.write_all(headers.as_bytes()).await.expect("response headers");
            // Keep the socket open but never send the declared body.
            std::future::pending::<()>().await;
        };
        tokio::pin!(stalled_body);
        let result = tokio::select! {
            _ = &mut stalled_body => panic!("body fixture must stay open"),
            result = timeout(channel.receive(), Duration::from_secs(4)) => result,
        };
        assert!(matches!(result.expect("body deadline"), Err(HttpError::RendezvousExpired)));
    }

    #[async_test]
    async fn test_independent_ready_future_finishing_after_deadline_is_rejected() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let result = before_deadline(deadline, async {
            // A response can become ready in a poll that itself crosses expiry.
            std::thread::sleep(Duration::from_millis(40));
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(HttpError::RendezvousExpired)));
    }

    #[async_test]
    async fn test_independent_expired_future_is_never_polled() {
        let deadline = Instant::now() - Duration::from_millis(1);
        let result = before_deadline::<()>(deadline, async {
            panic!("expired operation must never start");
        })
        .await;
        assert!(matches!(result, Err(HttpError::RendezvousExpired)));
    }

    #[async_test]
    async fn test_independent_initial_inbound_body_observes_advertised_expiry() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        for status in ["200 OK", "404 Not Found"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let url =
                Url::parse(&format!("http://{}/channel", listener.local_addr().unwrap())).unwrap();
            let stalled_server = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                let expiry = ruma::http_headers::system_time_to_http_date(
                    &(SystemTime::now() + Duration::from_secs(2)),
                )
                .unwrap();
                let headers = format!(
                    "HTTP/1.1 {status}\r\nETag: 1\r\nExpires: {}\r\nLast-Modified: Wed, 07 Sep 2022 14:27:51 GMT\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\n",
                    expiry.to_str().unwrap(),
                );
                socket.write_all(headers.as_bytes()).await.unwrap();
                std::future::pending::<()>().await;
            };
            let client =
                HttpClient::new(reqwest::Client::new(), RequestConfig::new().disable_retry());
            let result = tokio::select! {
                _ = stalled_server => panic!("fixture must remain open"),
                result = timeout(Channel::create_inbound(client, &url), Duration::from_secs(4)) => result,
            };
            assert!(matches!(
                result.expect("inbound body should expire"),
                Err(HttpError::RendezvousExpired)
            ));
        }
    }

    #[async_test]
    async fn test_independent_send_error_body_observes_existing_deadline() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let server = MockServer::start().await;
        let mut channel = channel(&server).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        channel.rendezvous_url =
            Url::parse(&format!("http://{}/channel", listener.local_addr().unwrap())).unwrap();
        channel.deadline = Instant::now() + Duration::from_millis(100);
        let stalled_server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 100\r\n\r\n")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        };
        let result = tokio::select! {
            _ = stalled_server => panic!("fixture must remain open"),
            result = timeout(channel.send(vec![1]), Duration::from_secs(2)) => result,
        };
        assert!(matches!(
            result.expect("send error body should expire"),
            Err(HttpError::RendezvousExpired)
        ));
    }

    async fn mock_rendzvous_create(server: &MockServer, rendezvous_url: &Url) {
        server
            .register(
                Mock::given(method("POST"))
                    .and(path("/_matrix/client/unstable/org.matrix.msc4108/rendezvous"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .append_header("X-Max-Bytes", "10240")
                            .append_header("ETag", "1")
                            .append_header(
                                "Expires",
                                ruma::http_headers::system_time_to_http_date(
                                    &(SystemTime::now() + Duration::from_secs(300)),
                                )
                                .expect("valid expiry"),
                            )
                            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                            .set_body_json(json!({
                                "url": rendezvous_url,
                            })),
                    ),
            )
            .await;
    }

    #[async_test]
    async fn test_creation() {
        let server = MockServer::start().await;
        let url =
            Url::parse(&server.uri()).expect("We should be able to parse the example homeserver");
        let rendezvous_url =
            url.join("abcdEFG12345").expect("We should be able to create a rendezvous URL");

        mock_rendzvous_create(&server, &rendezvous_url).await;

        let client = HttpClient::new(reqwest::Client::new(), RequestConfig::new().disable_retry());

        let mut alice = Channel::create_outbound(client, &url)
            .await
            .expect("We should be able to create an outbound rendezvous channel");

        assert_eq!(
            alice.rendezvous_url(),
            &rendezvous_url,
            "Alice should have configured the rendezvous URL correctly."
        );

        assert_eq!(alice.etag, "1", "Alice should have remembered the ETAG the server gave us.");

        let mut bob = {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET")).and(path("/abcdEFG12345")).respond_with(
                        ResponseTemplate::new(200)
                            .append_header("Content-Type", "text/plain")
                            .append_header("ETag", "2")
                            .append_header(
                                "Expires",
                                ruma::http_headers::system_time_to_http_date(
                                    &(SystemTime::now() + Duration::from_secs(300)),
                                )
                                .expect("valid expiry"),
                            )
                            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT"),
                    ),
                )
                .await;

            let client = HttpClient::new(reqwest::Client::new(), RequestConfig::short_retry());
            let InboundChannelCreationResult { channel: bob, initial_message: _ } =
                Channel::create_inbound(client, &rendezvous_url).await.expect(
                    "We should be able to create a rendezvous channel from a received message",
                );

            assert_eq!(alice.rendezvous_url(), bob.rendezvous_url());

            bob
        };

        assert_eq!(bob.etag, "2", "Bob should have remembered the ETAG the server gave us.");

        {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path("/abcdEFG12345"))
                        .and(header("if-none-match", "1"))
                        .respond_with(
                            ResponseTemplate::new(304)
                                .append_header("ETag", "1")
                                .append_header("Content-Type", "text/plain")
                                .append_header(
                                    "Expires",
                                    ruma::http_headers::system_time_to_http_date(
                                        &(SystemTime::now() + Duration::from_secs(300)),
                                    )
                                    .expect("valid expiry"),
                                )
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT"),
                        ),
                )
                .await;

            let response = alice
                .receive_single_message()
                .await
                .expect("We should be able to wait for data on the rendezvous channel.");
            assert_eq!(response.status_code, StatusCode::NOT_MODIFIED);
        }

        {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("PUT"))
                        .and(path("/abcdEFG12345"))
                        .and(header("Content-Type", "text/plain"))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .append_header("ETag", "1")
                                .append_header(
                                    "Expires",
                                    ruma::http_headers::system_time_to_http_date(
                                        &(SystemTime::now() + Duration::from_secs(300)),
                                    )
                                    .expect("valid expiry"),
                                )
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT"),
                        ),
                )
                .await;

            bob.send(b"Hello world".to_vec())
                .await
                .expect("We should be able to send data to the rendezouvs server.");
        }

        {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path("/abcdEFG12345"))
                        .and(header("if-none-match", "1"))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .append_header("ETag", "3")
                                .append_header("Content-Type", "text/plain")
                                .append_header(
                                    "Expires",
                                    ruma::http_headers::system_time_to_http_date(
                                        &(SystemTime::now() + Duration::from_secs(300)),
                                    )
                                    .expect("valid expiry"),
                                )
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                                .set_body_string("Hello world"),
                        ),
                )
                .await;

            let response = alice
                .receive_single_message()
                .await
                .expect("We should be able to wait and get data on the rendezvous channel.");

            assert_eq!(response.status_code, StatusCode::OK);
            assert_eq!(response.body, b"Hello world");
            assert_eq!(response.content_type, TEXT_PLAIN_CONTENT_TYPE);
        }
    }

    #[async_test]
    async fn test_retry_mechanism() {
        let server = MockServer::start().await;
        let url =
            Url::parse(&server.uri()).expect("We should be able to parse the example homeserver");
        let rendezvous_url =
            url.join("abcdEFG12345").expect("We should be able to create a rendezvous URL");
        mock_rendzvous_create(&server, &rendezvous_url).await;

        let client = HttpClient::new(reqwest::Client::new(), RequestConfig::new().disable_retry());

        let mut alice = Channel::create_outbound(client, &url)
            .await
            .expect("We should be able to create an outbound rendezvous channel");

        server
            .register(
                Mock::given(method("GET"))
                    .and(path("/abcdEFG12345"))
                    .and(header("if-none-match", "1"))
                    .respond_with(
                        ResponseTemplate::new(304)
                            .append_header("ETag", "2")
                            .append_header("Content-Type", "text/plain")
                            .append_header(
                                "Expires",
                                ruma::http_headers::system_time_to_http_date(
                                    &(SystemTime::now() + Duration::from_secs(300)),
                                )
                                .expect("valid expiry"),
                            )
                            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                            .set_body_string(""),
                    )
                    .expect(1),
            )
            .await;

        server
            .register(
                Mock::given(method("GET"))
                    .and(path("/abcdEFG12345"))
                    .and(header("if-none-match", "2"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .append_header("ETag", "3")
                            .append_header("Content-Type", "text/plain")
                            .append_header(
                                "Expires",
                                ruma::http_headers::system_time_to_http_date(
                                    &(SystemTime::now() + Duration::from_secs(300)),
                                )
                                .expect("valid expiry"),
                            )
                            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                            .set_body_string("Hello world"),
                    )
                    .expect(1),
            )
            .await;

        let response = alice
            .receive()
            .await
            .expect("We should be able to wait and get data on the rendezvous channel.");

        assert_eq!(response, b"Hello world");
    }

    #[async_test]
    async fn test_receive_error() {
        let server = MockServer::start().await;
        let url =
            Url::parse(&server.uri()).expect("We should be able to parse the example homeserver");
        let rendezvous_url =
            url.join("abcdEFG12345").expect("We should be able to create a rendezvous URL");
        mock_rendzvous_create(&server, &rendezvous_url).await;

        let client = HttpClient::new(reqwest::Client::new(), RequestConfig::new().disable_retry());

        let mut alice = Channel::create_outbound(client, &url)
            .await
            .expect("We should be able to create an outbound rendezvous channel");

        {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path("/abcdEFG12345"))
                        .and(header("if-none-match", "1"))
                        .respond_with(
                            ResponseTemplate::new(404)
                                .append_header("ETag", "1")
                                .append_header("Content-Type", "text/plain")
                                .append_header(
                                    "Expires",
                                    ruma::http_headers::system_time_to_http_date(
                                        &(SystemTime::now() + Duration::from_secs(300)),
                                    )
                                    .expect("valid expiry"),
                                )
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                                .set_body_string(""),
                        )
                        .expect(1),
                )
                .await;

            alice.receive().await.expect_err("We should return an error if we receive a 404");
        }

        {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path("/abcdEFG12345"))
                        .and(header("if-none-match", "1"))
                        .respond_with(
                            ResponseTemplate::new(504)
                                .append_header("ETag", "1")
                                .append_header("Content-Type", "text/plain")
                                .append_header(
                                    "Expires",
                                    ruma::http_headers::system_time_to_http_date(
                                        &(SystemTime::now() + Duration::from_secs(300)),
                                    )
                                    .expect("valid expiry"),
                                )
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT")
                                .set_body_json(json!({
                                  "errcode": "M_NOT_FOUND",
                                  "error": "No resource was found for this request.",
                                })),
                        )
                        .expect(1),
                )
                .await;

            alice
                .receive()
                .await
                .expect_err("We should return an error if we receive a gateway timeout");
        }
    }
}
