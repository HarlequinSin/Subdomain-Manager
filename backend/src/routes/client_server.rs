use crate::{
    models::{ClientAssignmentResponse, PutClientAssignmentRequest},
    services::manager,
};
use axum::http::StatusCode;
use serde::Serialize;
use shared::{
    ApiError, GetState, Payload,
    models::{server::GetServer, user::GetPermissionManager},
    response::{ApiResponse, ApiResponseResult},
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::State;

mod get_assignment {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        subdomain: ClientAssignmentResponse,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = FORBIDDEN, body = ApiError),
    ), params(("server" = uuid::Uuid, description = "The server ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
    ) -> ApiResponseResult {
        permissions.has_server_permission("allocations.read")?;

        let assignment = manager::get_client_assignment(&state, server.uuid).await?;
        let managed_domains = manager::list_managed_domains(&state).await?;

        ApiResponse::new_serialized(Response {
            subdomain: ClientAssignmentResponse {
                assignment,
                managed_domains,
            },
        })
        .ok()
    }
}

mod put_assignment {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        assignment: crate::models::ApiAssignment,
    }

    #[utoipa::path(put, path = "/", request_body = PutClientAssignmentRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ), params(("server" = uuid::Uuid, description = "The server ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
        Payload(request): Payload<PutClientAssignmentRequest>,
    ) -> ApiResponseResult {
        permissions.has_server_permission("allocations.update")?;

        if let Err(errors) = shared::utils::validate_data(&request) {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let assignment = manager::assign_server_subdomain(&state, &server, request).await?;

        ApiResponse::new_serialized(Response { assignment }).ok()
    }
}

mod delete_assignment {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = FORBIDDEN, body = ApiError),
    ), params(("server" = uuid::Uuid, description = "The server ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
    ) -> ApiResponseResult {
        permissions.has_server_permission("allocations.update")?;

        manager::clear_server_assignment(&state, server.uuid).await?;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get_assignment::route))
        .routes(routes!(put_assignment::route))
        .routes(routes!(delete_assignment::route))
        .with_state(state.clone())
}
