use crate::{
    api::{
        self,
        identity::group::{
            requests::{
                CreateGroupByNameRequest, CreateGroupByNameRequestBuilder, CreateGroupRequest,
                CreateGroupRequestBuilder, DeleteGroupByIdRequest, DeleteGroupByNameRequest,
                ListGroupsByIdRequest, ListGroupsByNameRequest, ReadGroupByIdRequest,
                ReadGroupByNameRequest, UpdateGroupByIdRequest, UpdateGroupByIdRequestBuilder,
            },
            responses::{
                ListGroupsByIdResponse, ListGroupsByNameResponse, ReadGroupByIdResponse,
                ReadGroupByNameResponse,
            },
        },
    },
    client::Client,
    error::ClientError,
};

/// Creates or update a group.
///
/// See [CreateGroupRequest]
#[instrument(skip(client, opts), err)]
pub async fn create(
    client: &impl Client,
    name: &str,
    opts: Option<&mut CreateGroupRequestBuilder>,
) -> Result<(), ClientError> {
    let mut t = CreateGroupRequest::builder();
    let endpoint = opts.unwrap_or(&mut t).name(name).build().unwrap();
    api::exec_with_empty(client, endpoint).await
}

/// Reads group by `id`.
///
/// See [ReadGroupByIdRequest]
#[instrument(skip(client), err)]
pub async fn read_by_id(
    client: &impl Client,
    id: &str,
) -> Result<ReadGroupByIdResponse, ClientError> {
    let endpoint = ReadGroupByIdRequest::builder().id(id).build().unwrap();

    api::exec_with_result(client, endpoint).await
}

/// Reads group by `name`.
///
/// See [ReadGroupByNameRequest]
#[instrument(skip(client), err)]
pub async fn read_by_name(
    client: &impl Client,
    name: &str,
) -> Result<ReadGroupByNameResponse, ClientError> {
    let endpoint = ReadGroupByNameRequest::builder()
        .name(name)
        .build()
        .unwrap();

    api::exec_with_result(client, endpoint).await
}
/// Update group by `id`.
///
/// See [UpdateGroupByIdRequest]
#[instrument(skip(client, opts), err)]
pub async fn update_by_id(
    client: &impl Client,
    id: &str,
    opts: Option<&mut UpdateGroupByIdRequestBuilder>,
) -> Result<(), ClientError> {
    let mut t = UpdateGroupByIdRequest::builder();
    let endpoint = opts.unwrap_or(&mut t).id(id).build().unwrap();
    api::exec_with_empty(client, endpoint).await
}

/// Delete group by `id`.
///
/// See [DeleteGroupByIdRequest]
#[instrument(skip(client), err)]
pub async fn delete_by_id(client: &impl Client, id: &str) -> Result<(), ClientError> {
    let endpoint = DeleteGroupByIdRequest::builder().id(id).build().unwrap();
    api::exec_with_empty(client, endpoint).await
}

/// List groups by ID.
///
/// See [ListGroupsByIdRequest]
#[instrument(skip(client), err)]
pub async fn list_by_id(client: &impl Client) -> Result<ListGroupsByIdResponse, ClientError> {
    let endpoint = ListGroupsByIdRequest::builder().build().unwrap();
    api::exec_with_result(client, endpoint).await
}
/// Creates or update an group with the given `name`.
///
/// See [CreateGroupByNameRequest]
#[instrument(skip(client, opts), err)]
pub async fn create_or_update_by_name(
    client: &impl Client,
    name: &str,
    opts: Option<&mut CreateGroupByNameRequestBuilder>,
) -> Result<(), ClientError> {
    let mut t = CreateGroupByNameRequest::builder();
    let endpoint = opts.unwrap_or(&mut t).name(name).build().unwrap();
    api::exec_with_empty(client, endpoint).await
}

/// Delete group by `name`.
///
/// See [DeleteGroupByIdRequest]
#[instrument(skip(client), err)]
pub async fn delete_by_name(client: &impl Client, name: &str) -> Result<(), ClientError> {
    let endpoint = DeleteGroupByNameRequest::builder()
        .name(name)
        .build()
        .unwrap();
    api::exec_with_empty(client, endpoint).await
}

/// List entities by Name.
///
/// See [ListGroupsByNameRequest]
#[instrument(skip(client), err)]
pub async fn list_by_name(client: &impl Client) -> Result<ListGroupsByNameResponse, ClientError> {
    let endpoint = ListGroupsByNameRequest::builder().build().unwrap();
    api::exec_with_result(client, endpoint).await
}
