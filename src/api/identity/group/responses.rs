use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Response from executing
/// [CreateGroupRequest](crate::api::identity::requests::CreateGroupRequest)
#[derive(Deserialize, Debug, Serialize)]
pub struct CreateGroupResponse {
    pub id: String,
    pub name: Option<String>,
}

/// Response from executing
/// [ReadGroupByIdRequest](crate::api::identity::requests::ReadGroupByIdRequest)
#[derive(Deserialize, Debug, Serialize)]
pub struct ReadGroupByIdResponse {
    // TODO What's the type of Alias?
    // pub alias: Option<String>,
    pub creation_time: String,
    pub id: String,
    pub last_update_time: String,
    pub member_entity_ids: Vec<String>,
    pub member_group_ids: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, String>>,
    pub modify_index: u64,
    pub name: String,
    pub policies: Vec<String>,
    #[serde(rename = "type")]
    pub group_type: String,
}

/// Response from executing
/// [ListGroupsById](crate::api::identity::requests::ListGroupsById)
#[derive(Deserialize, Debug, Serialize)]
pub struct ListGroupsByIdResponse {
    pub keys: Vec<String>,
}

/// Response from executing
/// [ReadGroupByNameRequest](crate::api::identity::requests::ReadGroupByNameRequest)
#[derive(Deserialize, Debug, Serialize)]
pub struct ReadGroupByNameResponse {
    // TODO What's the type of Alias?
    // pub alias: Option<String>,
    pub creation_time: String,
    pub id: String,
    pub last_update_time: String,
    pub member_entity_ids: Vec<String>,
    pub member_group_ids: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, String>>,
    pub modify_index: u64,
    pub name: String,
    pub policies: Vec<String>,
    #[serde(rename = "type")]
    pub group_type: String,
}

/// Response from executing
/// [ListGroupsByName](crate::api::identity::requests::ListGroupsByName)
#[derive(Deserialize, Debug, Serialize)]
pub struct ListGroupsByNameResponse {
    pub keys: Vec<String>,
}
