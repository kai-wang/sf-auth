use std::{env, net::SocketAddr};

use async_session::MemoryStore;
use axum::{
    async_trait,
    extract::{
        rejection::TypedHeaderRejectionReason, FromRef, FromRequestParts, Query, State, TypedHeader,
    },
    http::{header::SET_COOKIE, HeaderMap},
    Router, routing::get, 
    response::{IntoResponse, Redirect, Response},
};
use headers::AcceptRanges;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl
};
use serde::{Deserialize, Serialize};

#[tokio::main]

async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "sf-auth=debug".into())
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = MemoryStore::new();
    let oauth_client = oauth_client();

    println!("{:#?}", &oauth_client);


    let app_state = AppState {
        store,
        oauth_client
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth", get(auth_callback))
        .route("/api/auth/callback/salesforce", get(login_authorized))
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

}

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    oauth_client: BasicClient,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for BasicClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

fn oauth_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID");
    let client_secret = env::var("CLIENT_SECRET").ok();
    let redirect_url = env::var("REDIRECT_URL").unwrap_or_else(|_| "http://localhost:3000/api/auth/callback/salesforce".to_string());

    let auth_url = env::var("AUTH_URL").unwrap_or_else(|_| "https://login.salesforce.com/services/oauth2/authorize?response_type=code".to_string());

    let token_url = env::var("TOKEN_URL").unwrap_or_else(|_| "https://login.salesforce.com/services/oauth2/token".to_string());

    BasicClient::new(
        ClientId::new(client_id),
        client_secret.map(|v| ClientSecret::new(v)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: String,
    avatar: Option<String>,
    username: String,
    discriminator: String,
}

async fn index() -> impl IntoResponse {
    "hello"
    // match user {
    //     Some(u) => format!(
    //         "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
    //         u.username
    //     ),
    //     None => "You're not logged in.\nVisit `/auth/discord` to do so.".to_string(),
    // }
}

async fn auth_callback(State(client): State<BasicClient>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("api".to_string()))
        .url();

    println!("{:#?}", auth_url);
    Redirect::to(auth_url.as_ref())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn login_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(oauth_client): State<BasicClient>,
) -> impl IntoResponse {
    // Get an auth token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .unwrap();

    println!("{:#?}", &token.access_token().secret());

    // Build the cookie
    let cookie = format!("{}={}; SameSite=Lax; Path=/", "SESSION", "token");

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    (headers, Redirect::to("/"))
}

async fn protected() {
    todo!()
}

async fn logout() {
    todo!()
}