use shared::State;
use utoipa_axum::router::OpenApiRouter;

pub mod admin;
pub mod client_server;

pub fn admin_router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/subdomain-manager", admin::router(state))
        .with_state(state.clone())
}

pub fn client_server_router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/subdomain-manager", client_server::router(state))
        .with_state(state.clone())
}
