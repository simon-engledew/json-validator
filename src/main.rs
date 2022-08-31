use std::env;
use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;
use std::path::Path;

use jsonschema::{Draft, JSONSchema};
use serde_json;
use actix_web::{error, web, get, post, App, HttpServer, HttpRequest};


#[get("/_ping")]
async fn ping(_req: HttpRequest) -> impl actix_web::Responder {
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
            continue
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

#[post("/validate/{path}")]
async fn validate(schemas: web::Data<HashMap<String, JSONSchema>>, document: web::Json<serde_json::Value>, info: web::Path<(String,)>) -> actix_web::Result<impl actix_web::Responder> {
    let info = info.into_inner();

    let schema = schemas.get(&info.0).ok_or(error::ErrorNotFound("not found"))?;

    schema.validate(&document).map_err(|errors| error::ErrorBadRequest(get_message(errors)))?;

    Ok("")
}

fn load_schemas(paths: impl IntoIterator<Item = String>) -> Result<HashMap<String, JSONSchema>, std::io::Error> {
    let mut schemas = HashMap::new();

    for path_string in paths {
        let path = Path::new(&path_string);
        let name = path.file_stem().and_then(|v|v.to_str()).ok_or(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to process {}", path_string)))?;

        println!("Loading {}", path_string);

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let doc = serde_json::from_reader(reader)?;
        let schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&doc)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to compile schema {}: {}", path_string, format_error(err))))?;

        schemas.insert(String::from(name), schema);
    }

    Ok(schemas)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let schemas = web::Data::new(load_schemas(env::args().skip(1)).expect("Failed to load schemas"));

    let bind = env::var("ADDR").unwrap_or(String::from("127.0.0.1:8080"));

    println!("Listening on {}", bind);

    HttpServer::new(move || App::new()
            .app_data(web::Data::new(web::JsonConfig::default().limit(1024 * 1024 * 500)))
            .app_data(schemas.clone())
            .service(ping)
            .service(validate)
        )
        .bind(bind)?
        .run()
        .await
}
