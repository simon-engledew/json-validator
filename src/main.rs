use actix_web;
use env_logger;
use jsonschema;
use log;
use serde_json;
use walkdir;

type SchemaMap = std::collections::HashMap<String, jsonschema::JSONSchema>;

#[actix_web::get("/_ping")]
async fn ping(_req: actix_web::HttpRequest) -> impl actix_web::Responder {
    "OK"
}

fn format_error(err: jsonschema::ValidationError) -> String {
    let path = err.instance_path.to_string();

    if path.is_empty() {
        err.to_string()
    } else {
        format!("{}: {}", path, err.to_string())
    }
}

fn get_message(errors: jsonschema::ErrorIterator) -> String {
    let iter = errors.enumerate();
    let mut out = String::with_capacity(560);
    let mut rest = 0;

    for (i, err) in iter {
        if out.len() > 512 {
            rest += 1;
            continue;
        }

        if i > 0 {
            out.push_str(", ");
        }

        out.push_str(&format_error(err));
    }

    if rest > 1 {
        out.push_str(&format!(" and {} other errors", rest));
    } else if rest > 0 {
        out.push_str(" and 1 other error");
    }

    out
}

#[actix_web::post("/{path:.*}")]
async fn validate(
    schemas: actix_web::web::Data<SchemaMap>,
    document: actix_web::web::Json<serde_json::Value>,
    info: actix_web::web::Path<(String,)>,
) -> actix_web::Result<impl actix_web::Responder> {
    let info = info.into_inner();

    let schema = schemas
        .get(&info.0)
        .ok_or(actix_web::error::ErrorNotFound("not found"))?;

    schema
        .validate(&document)
        .map_err(|errors| actix_web::error::ErrorBadRequest(get_message(errors)))?;

    Ok("")
}

#[derive(Debug)]
enum LoadError {
    Read(String, std::io::Error),
    Parse(String, serde_json::Error),
    Compile(String, String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LoadError::Read(path, err) => write!(f, "Failed to read schema {}: {}", path, err),
            LoadError::Parse(path, err) => {
                write!(f, "Failed to parse schema {}: {}", path, err)
            }
            LoadError::Compile(path, msg) => {
                write!(f, "Failed to compile schema {}: {}", path, msg)
            }
        }
    }
}

fn to_key(path: &std::path::Path) -> String {
    let key = String::from(path.strip_prefix("./").unwrap_or(&path).to_string_lossy());

    String::from(key.strip_suffix(".json").unwrap_or(&key))
}

fn load_schemas(paths: impl IntoIterator<Item = String>) -> Result<SchemaMap, LoadError> {
    let mut schemas = SchemaMap::new();

    for path_string in paths {
        for path in walkdir::WalkDir::new(&path_string)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !e.file_type().is_dir())
            .map(|e| e.into_path())
            .filter(|path| {
                path.extension()
                    .map(|extension| extension == "json")
                    .unwrap_or(false)
            })
        {
            let key = to_key(&path);

            log::debug!("Considering {}", key);

            let schema = std::fs::File::open(path)
                .map_err(|err| LoadError::Read(String::from(key.as_str()), err))
                .and_then(|file| {
                    serde_json::from_reader(std::io::BufReader::new(file))
                        .map_err(|err| LoadError::Parse(String::from(key.as_str()), err))
                })
                .and_then(|doc| {
                    jsonschema::JSONSchema::options()
                        .with_draft(jsonschema::Draft::Draft7)
                        .compile(&doc)
                        .map_err(|err| {
                            LoadError::Compile(String::from(key.as_str()), err.to_string())
                        })
                })?;

            log::info!("Loaded {}", key);
            schemas.insert(key, schema);
        }
    }

    Ok(schemas)
}

fn config(
    schemas: &actix_web::web::Data<SchemaMap>,
) -> impl FnOnce(&mut actix_web::web::ServiceConfig) + '_ {
    move |cfg: &mut actix_web::web::ServiceConfig| {
        cfg.app_data(actix_web::web::Data::new(
            actix_web::web::JsonConfig::default().limit(1024 * 1024 * 500),
        ))
        .app_data(actix_web::web::Data::clone(schemas))
        .service(ping)
        .service(validate);
    }
}

macro_rules! either_iter {
    {
        if $($rest:tt)*
    } => {
        either_iter_parser! {
            predicate = ()
            rest = ($($rest)*)
        }
    };
}

macro_rules! either_iter_parser {
    {
        predicate = ($($predicate:tt)*)
        rest = ({ $($then:tt)* } else { $($else:tt)* })
    } => {
        either_iter($($predicate)*, $($then)*, $($else)*)
    };

    {
        predicate = ($($predicate:tt)*)
        rest = ($next:tt $($rest:tt)*)
    } => {
        either_iter_parser! {
            predicate = ($($predicate)* $next)
            rest = ($($rest)*)
        }
    };
}

fn either_iter<T>(
    pred: bool,
    a: impl Iterator<Item = T>,
    b: impl Iterator<Item = T>,
) -> impl Iterator<Item = T> {
    let iter_a = if pred { Some(a) } else { None };
    let iter_b = if !pred { Some(b) } else { None };

    iter_a
        .into_iter()
        .flatten()
        .chain(iter_b.into_iter().flatten())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let paths = either_iter! {
        if std::env::args().len() > 1 {
            std::env::args().skip(1)
        } else {
            std::iter::once(String::from("."))
        }
    };

    let schemas = actix_web::web::Data::new(load_schemas(paths).expect("failed to load schemas"));
    let bind = std::env::var("ADDR").unwrap_or(String::from("127.0.0.1:8080"));

    log::info!("starting server at http://{}", bind);

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(actix_web::middleware::Logger::default())
            .configure(config(&schemas))
    })
    .bind(bind)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_validation() {
        let schemas = actix_web::web::Data::new(
            load_schemas(vec![String::from("schemas/names.json")]).expect("ok"),
        );
        let app =
            actix_web::test::init_service(actix_web::App::new().configure(config(&schemas))).await;
        let req = actix_web::test::TestRequest::post()
            .insert_header(actix_web::http::header::ContentType::json())
            .uri("/schemas/names.json")
            .set_payload("{}")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let result = actix_web::test::read_body(resp).await;
        assert_eq!(
            result,
            actix_web::web::Bytes::from_static(
                b"\"name\" is a required property, \"age\" is a required property"
            )
        );
    }
}
