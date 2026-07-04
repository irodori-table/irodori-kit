//! Stable metadata DTOs for app and extension command boundaries.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::metadata::{
    ColumnMetadata as CacheColumnMetadata, ForeignKeyMetadata as CacheForeignKeyMetadata,
    IndexMetadata as CacheIndexMetadata, MetadataObjectKind, MetadataSnapshot,
    ObjectMetadata as CacheObjectMetadata, QuickSample as CacheQuickSample, RoutineKind,
    RoutineMetadata as CacheRoutineMetadata, SchemaMetadata as CacheSchemaMetadata,
};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct DatabaseMetadata {
    pub schemas: Vec<SchemaMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct SchemaMetadata {
    pub name: String,
    pub objects: Vec<DbObjectMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct DbObjectMetadata {
    pub schema: String,
    pub name: String,
    pub kind: DbObjectMetadataKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ddl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub row_estimate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub sample: Option<DbQuickSample>,
    pub columns: Vec<ColumnMetadata>,
    pub indexes: Vec<IndexMetadata>,
    #[serde(default)]
    pub primary_key: Vec<String>,
    #[serde(default)]
    pub foreign_keys: Vec<ForeignKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ForeignKey {
    pub columns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub references_schema: Option<String>,
    pub references_table: String,
    pub references_columns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct DbQuickSample {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum DbObjectMetadataKind {
    Table,
    View,
    Index,
    Procedure,
    Function,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ColumnMetadata {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub ordinal: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub default_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct IndexMetadata {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

pub fn metadata_to_snapshot(connection_id: &str, metadata: &DatabaseMetadata) -> MetadataSnapshot {
    let mut snapshot = MetadataSnapshot::new(connection_id, 1, std::time::SystemTime::now());
    for schema in &metadata.schemas {
        let mut cache_schema = CacheSchemaMetadata::new(&schema.name);
        for object in &schema.objects {
            match object.kind {
                DbObjectMetadataKind::Table | DbObjectMetadataKind::View => {
                    cache_schema.objects.push(object_to_cache(object));
                }
                DbObjectMetadataKind::Procedure | DbObjectMetadataKind::Function => {
                    cache_schema.routines.push(routine_to_cache(object));
                }
                DbObjectMetadataKind::Index => {}
            }
        }
        snapshot.schemas.push(cache_schema);
    }
    snapshot
}

pub fn snapshot_to_metadata(snapshot: &MetadataSnapshot) -> DatabaseMetadata {
    DatabaseMetadata {
        schemas: snapshot
            .schemas
            .iter()
            .map(|schema| SchemaMetadata {
                name: schema.name.clone(),
                objects: snapshot_schema_objects(schema),
            })
            .collect(),
    }
}

fn object_to_cache(object: &DbObjectMetadata) -> CacheObjectMetadata {
    let mut cache_object = if object.kind == DbObjectMetadataKind::View {
        CacheObjectMetadata::view(&object.name)
    } else {
        CacheObjectMetadata::table(&object.name)
    };
    cache_object.comment = object.comment.clone();
    cache_object.ddl = object.ddl.clone();
    cache_object.row_estimate = object.row_estimate;
    cache_object.sample = object.sample.as_ref().map(|sample| CacheQuickSample {
        columns: sample.columns.clone(),
        rows: sample.rows.clone(),
        truncated: sample.truncated,
    });
    cache_object
        .columns
        .extend(object.columns.iter().map(column_to_cache));
    cache_object
        .indexes
        .extend(object.indexes.iter().map(|index| {
            let mut cache_index = CacheIndexMetadata::new(&index.name, index.columns.clone());
            cache_index.unique = index.unique;
            cache_index.primary = object.primary_key.contains(&index.name)
                || index
                    .columns
                    .iter()
                    .all(|column| object.primary_key.contains(column));
            cache_index
        }));
    cache_object
        .foreign_keys
        .extend(object.foreign_keys.iter().map(|foreign_key| {
            CacheForeignKeyMetadata::new(
                foreign_key.columns.clone(),
                foreign_key.references_schema.clone().unwrap_or_default(),
                &foreign_key.references_table,
                foreign_key.references_columns.clone(),
            )
        }));
    cache_object
}

fn column_to_cache(column: &ColumnMetadata) -> CacheColumnMetadata {
    let mut cache_column = CacheColumnMetadata::new(
        &column.name,
        &column.data_type,
        column.nullable,
        column.ordinal as u32,
    );
    cache_column.default_value = column.default_value.clone();
    cache_column.comment = column.comment.clone();
    cache_column
}

fn routine_to_cache(object: &DbObjectMetadata) -> CacheRoutineMetadata {
    if object.kind == DbObjectMetadataKind::Function {
        CacheRoutineMetadata::new(&object.name, "()")
    } else {
        CacheRoutineMetadata::procedure(&object.name, "()")
    }
}

fn snapshot_schema_objects(schema: &CacheSchemaMetadata) -> Vec<DbObjectMetadata> {
    let mut objects: Vec<_> = schema
        .objects
        .iter()
        .map(|object| snapshot_object(schema, object))
        .collect();
    objects.extend(
        schema
            .routines
            .iter()
            .map(|routine| snapshot_routine(schema, routine)),
    );
    objects
}

fn snapshot_object(schema: &CacheSchemaMetadata, object: &CacheObjectMetadata) -> DbObjectMetadata {
    let kind = match object.kind {
        MetadataObjectKind::View => DbObjectMetadataKind::View,
        _ => DbObjectMetadataKind::Table,
    };
    let indexes: Vec<_> = object
        .indexes
        .iter()
        .map(|index| IndexMetadata {
            name: index.name.clone(),
            columns: index.columns.clone(),
            unique: index.unique,
        })
        .collect();
    let primary_key = object
        .indexes
        .iter()
        .find(|index| index.primary)
        .map(|index| index.columns.clone())
        .unwrap_or_default();
    DbObjectMetadata {
        schema: schema.name.clone(),
        name: object.name.clone(),
        kind,
        comment: object.comment.clone(),
        ddl: object.ddl.clone(),
        row_estimate: object.row_estimate,
        sample: object.sample.as_ref().map(|sample| DbQuickSample {
            columns: sample.columns.clone(),
            rows: sample.rows.clone(),
            truncated: sample.truncated,
        }),
        columns: object
            .columns
            .iter()
            .map(|column| ColumnMetadata {
                name: column.name.clone(),
                data_type: column.data_type.clone(),
                nullable: column.nullable,
                ordinal: column.ordinal as i32,
                default_value: column.default_value.clone(),
                comment: column.comment.clone(),
            })
            .collect(),
        indexes,
        primary_key,
        foreign_keys: object
            .foreign_keys
            .iter()
            .map(|foreign_key| ForeignKey {
                columns: foreign_key.columns.clone(),
                references_schema: Some(foreign_key.references_schema.clone()),
                references_table: foreign_key.references_object.clone(),
                references_columns: foreign_key.references_columns.clone(),
            })
            .collect(),
    }
}

fn snapshot_routine(
    schema: &CacheSchemaMetadata,
    routine: &CacheRoutineMetadata,
) -> DbObjectMetadata {
    let kind = match routine.kind {
        RoutineKind::Function => DbObjectMetadataKind::Function,
        RoutineKind::Procedure => DbObjectMetadataKind::Procedure,
    };
    DbObjectMetadata {
        schema: schema.name.clone(),
        name: routine.name.clone(),
        kind,
        comment: None,
        ddl: None,
        row_estimate: None,
        sample: None,
        columns: Vec::new(),
        indexes: Vec::new(),
        primary_key: Vec::new(),
        foreign_keys: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_metadata_to_snapshot_and_back() {
        let metadata = DatabaseMetadata {
            schemas: vec![SchemaMetadata {
                name: "public".to_string(),
                objects: vec![DbObjectMetadata {
                    schema: "public".to_string(),
                    name: "users".to_string(),
                    kind: DbObjectMetadataKind::Table,
                    comment: Some("accounts".to_string()),
                    ddl: None,
                    row_estimate: Some(10),
                    sample: Some(DbQuickSample {
                        columns: vec!["id".to_string()],
                        rows: vec![vec!["1".to_string()]],
                        truncated: false,
                    }),
                    columns: vec![ColumnMetadata {
                        name: "id".to_string(),
                        data_type: "integer".to_string(),
                        nullable: false,
                        ordinal: 1,
                        default_value: None,
                        comment: None,
                    }],
                    indexes: vec![IndexMetadata {
                        name: "users_pkey".to_string(),
                        columns: vec!["id".to_string()],
                        unique: true,
                    }],
                    primary_key: vec!["id".to_string()],
                    foreign_keys: Vec::new(),
                }],
            }],
        };

        let snapshot = metadata_to_snapshot("local", &metadata);
        let roundtrip = snapshot_to_metadata(&snapshot);

        assert_eq!(roundtrip.schemas[0].objects[0].name, "users");
        assert_eq!(roundtrip.schemas[0].objects[0].primary_key, ["id"]);
        assert_eq!(
            roundtrip.schemas[0].objects[0].columns[0].data_type,
            "integer"
        );
    }
}
