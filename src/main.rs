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

#[post("/{path:.*}")]
async fn validate(schemas: web::Data<&'static HashMap<String, JSONSchema>>, document: web::Json<serde_json::Value>, info: web::Path<(String,)>) -> actix_web::Result<impl actix_web::Responder> {
    let info = info.into_inner();

    let schema = schemas.get(&info.0).ok_or(error::ErrorNotFound("not found"))?;

    schema.validate(&document).map_err(|errors| error::ErrorBadRequest(get_message(errors)))?;

    Ok("")
}

fn load_schemas(paths: impl IntoIterator<Item = String>) -> Result<&'static HashMap<String, JSONSchema>, std::io::Error> {
    let mut schemas = HashMap::new();

    for path_string in paths {
        let path = Path::new(&path_string);

        println!("Loading {}", path_string);

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let doc = serde_json::from_reader(reader)?;
        let schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&doc)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to compile schema {}: {}", path_string, format_error(err))))?;

        schemas.insert(String::from(path.to_string_lossy()), schema);
    }

    Ok(Box::leak(Box::new(schemas)))
}

fn config(schemas: &'static HashMap<String, JSONSchema>) -> impl Fn(&mut web::ServiceConfig) {
    move |cfg: &mut web::ServiceConfig| {
        cfg
            .app_data(web::Data::new(web::JsonConfig::default().limit(1024 * 1024 * 500)))
            .app_data(web::Data::new(schemas))
            .service(ping)
            .service(validate);
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let schemas: &'static HashMap<String, JSONSchema> = load_schemas(env::args().skip(1)).expect("Failed to load schemas");
    let bind = env::var("ADDR").unwrap_or(String::from("127.0.0.1:8080"));

    println!("Listening on {}", bind);

    HttpServer::new(move || App::new().configure(config(&schemas)))
        .bind(bind)?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        http::{header::ContentType, StatusCode},
        web::{Bytes},
        test,
    };

    #[actix_web::test]
    async fn test_validation() {
        let schemas = load_schemas(vec![String::from("schemas/names.json")]).expect("ok");
        let app = test::init_service(App::new().configure(config(&schemas))).await;
        let req = test::TestRequest::post()
            .insert_header(ContentType::json())
            .uri("/schemas/names.json")
            .set_payload("{}")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = test::read_body(resp).await;
        assert_eq!(result, Bytes::from_static(b"\"name\" is a required property, \"age\" is a required property"));
    }
}
