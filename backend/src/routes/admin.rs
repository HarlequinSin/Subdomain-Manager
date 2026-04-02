use crate::{
    models::{
        AdminConfigResponse, AdminReconcileRequest, AdminReconcileResponse,
        AdminUpsertAliasRuleRequest, AdminUpsertBlacklistRuleRequest,
        AdminUpsertManagedDomainRequest, AdminUpsertProviderRequest,
        AdminUpsertRecordTemplateRequest,
    },
    services::manager,
    validation,
};
use axum::http::StatusCode;
use serde::Serialize;
use shared::{
    ApiError, GetState, Payload,
    models::user::GetPermissionManager,
    response::{ApiResponse, ApiResponseResult},
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::State;

mod get_config {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        config: AdminConfigResponse,
    }

    #[utoipa::path(get, path = "/config", responses(
        (status = OK, body = inline(Response)),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(state: GetState, permissions: GetPermissionManager) -> ApiResponseResult {
        permissions.has_admin_permission("settings.read")?;

        let config = manager::get_admin_config(&state).await?;

        ApiResponse::new_serialized(Response { config }).ok()
    }
}

mod put_provider {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        provider: crate::models::ApiProvider,
    }

    #[utoipa::path(put, path = "/providers", request_body = AdminUpsertProviderRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Payload(request): Payload<AdminUpsertProviderRequest>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("settings.update")?;

        if let Err(errors) = shared::utils::validate_data(&request) {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let provider = manager::upsert_provider(&state, &request.name, &request.api_token, request.enabled).await?;

        ApiResponse::new_serialized(Response { provider }).ok()
    }
}

mod put_managed_domain {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        managed_domain: crate::models::ApiManagedDomain,
    }

    #[utoipa::path(put, path = "/domains", request_body = AdminUpsertManagedDomainRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Payload(request): Payload<AdminUpsertManagedDomainRequest>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("settings.update")?;

        if let Err(errors) = shared::utils::validate_data(&request) {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        if let Err(err) = validation::validate_domain(&request.base_domain) {
            return ApiResponse::error(err.to_string())
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let managed_domain = match manager::upsert_managed_domain(
            &state,
            request.provider_uuid,
            &request.display_name,
            &request.base_domain,
            &request.zone_name,
            &request.zone_id,
            request.default_ttl,
            request.default_proxied,
            request.game.as_deref(),
            request.allow_user_updates,
            &request.allowed_record_types,
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                return ApiResponse::error(err.to_string())
                    .with_status(StatusCode::BAD_REQUEST)
                    .ok();
            }
        };

        ApiResponse::new_serialized(Response { managed_domain }).ok()
    }
}

mod put_blacklist_rule {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        blacklist_rule: crate::models::ApiBlacklistRule,
    }

    #[utoipa::path(put, path = "/blacklist-rules", request_body = AdminUpsertBlacklistRuleRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Payload(request): Payload<AdminUpsertBlacklistRuleRequest>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("settings.update")?;

        if let Err(errors) = shared::utils::validate_data(&request) {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        if let Err(err) = validation::validate_regex(&request.pattern) {
            return ApiResponse::error(err.to_string())
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let blacklist_rule = manager::upsert_blacklist_rule(
            &state,
            request.managed_domain_uuid,
            &request.pattern,
            request.case_sensitive,
            request.enabled,
            request.description.as_deref(),
        )
        .await?;

        ApiResponse::new_serialized(Response { blacklist_rule }).ok()
    }
}

mod put_alias_rule {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        alias_rule: crate::models::ApiAliasRule,
    }

    #[utoipa::path(put, path = "/alias-rules", request_body = AdminUpsertAliasRuleRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Payload(request): Payload<AdminUpsertAliasRuleRequest>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("settings.update")?;

        if let Err(errors) = shared::utils::validate_data(&request) {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let alias_rule =
            manager::upsert_alias_rule(&state, request.managed_domain_uuid, &request.source, &request.target, request.enabled)
                .await?;

        ApiResponse::new_serialized(Response { alias_rule }).ok()
    }
}

mod put_record_template {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        record_template: crate::models::ApiRecordTemplate,
    }

    #[utoipa::path(put, path = "/record-templates", request_body = AdminUpsertRecordTemplateRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Payload(request): Payload<AdminUpsertRecordTemplateRequest>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("settings.update")?;

        if let Err(errors) = shared::utils::validate_data(&request) {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let record_type = validation::normalize_record_type(&request.record_type);
        if let Err(err) = validation::validate_record_type(&record_type) {
            return ApiResponse::error(err.to_string())
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let record_template = manager::upsert_record_template(
            &state,
            request.managed_domain_uuid,
            request.egg_uuid,
            request.game.as_deref(),
            &record_type,
            &request.content_template,
            request.ttl,
            request.proxied,
            request.priority,
            request.weight,
            request.port,
            request.service.as_deref(),
            request.protocol.as_deref(),
            request.only_non_default_port,
            request.enabled,
        )
        .await?;

        ApiResponse::new_serialized(Response { record_template }).ok()
    }
}

mod post_reconcile {
    use super::*;

    #[derive(ToSchema, Serialize)]
    struct Response {
        reconcile: AdminReconcileResponse,
    }

    #[utoipa::path(post, path = "/reconcile", request_body = AdminReconcileRequest, responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = FORBIDDEN, body = ApiError),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Payload(request): Payload<AdminReconcileRequest>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("settings.update")?;

        let assignment = manager::reconcile_server_assignment(&state, request.server_uuid, request.dry_run).await?;

        ApiResponse::new_serialized(Response {
            reconcile: AdminReconcileResponse {
                assignment,
                dry_run: request.dry_run,
            },
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get_config::route))
        .routes(routes!(put_provider::route))
        .routes(routes!(put_managed_domain::route))
        .routes(routes!(put_blacklist_rule::route))
        .routes(routes!(put_alias_rule::route))
        .routes(routes!(put_record_template::route))
        .routes(routes!(post_reconcile::route))
        .with_state(state.clone())
}
