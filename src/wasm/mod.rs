extern crate console_error_panic_hook;

use std::str::FromStr;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;
use wasm_logger;

use crate::data_types::credential::Credential;
use crate::data_types::cred_def::SignatureType;
use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::cred_offer::CredentialOffer;
use crate::data_types::cred_request::CredentialRequestMetadata;
use crate::data_types::pres_request::PresentationRequest;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::link_secret::LinkSecret;

use crate::services::issuer;
use crate::services::prover;
use crate::services::utils::new_nonce;

use crate::types::CredentialDefinitionConfig;
use crate::types::PresentCredentials;

use crate::utils::validation::Validatable;

mod error;
use self::error::ErrorCode;

#[wasm_bindgen(js_name = anoncredsSetDefaultLogger)]
pub fn anoncreds_set_default_logger() -> ErrorCode {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Trace));
    debug!("Initialized default logger");

    ErrorCode::Success
}

#[wasm_bindgen(js_name = anoncredsCreateSchema)]
pub fn anoncreds_create_schema(
    name: &str,
    version: &str,
    issuer_id: &str,
    attribute_names: Vec<JsValue>,
) -> JsValue {
    let mut attribute_names_vec: Vec<String> = vec![];

    for name in &attribute_names {
        let name = name.as_string();
        if let Some(name) = name {
            attribute_names_vec.push(name.to_owned());
        }
    }

    let schema =
        issuer::create_schema(name, version, issuer_id, attribute_names_vec.into()).unwrap();

    serde_wasm_bindgen::to_value(&schema).unwrap()
}

#[wasm_bindgen(js_name = anoncredsCreateCredentialDefinition)]
pub fn anoncreds_create_credential_definition(
    schema_id: &str,
    schema: JsValue,
    tag: &str,
    issuer_id: &str,
    signature_type: &str,
    support_revocation: bool,
) -> Vec<JsValue> {
    let schema: Schema = serde_wasm_bindgen::from_value(schema).unwrap();
    let signature_type = SignatureType::from_str(signature_type)
        .map_err(err_map!(Input))
        .unwrap();
    let (cred_def, cred_def_pvt, key_proof) = issuer::create_credential_definition(
        schema_id,
        &schema,
        issuer_id,
        tag,
        signature_type,
        CredentialDefinitionConfig { support_revocation },
    )
    .unwrap();

    let cred_def = serde_wasm_bindgen::to_value(&cred_def).unwrap();
    let cred_def_pvt = serde_wasm_bindgen::to_value(&cred_def_pvt).unwrap();
    let key_proof = serde_wasm_bindgen::to_value(&key_proof).unwrap();

    vec![cred_def, cred_def_pvt, key_proof]
}

#[wasm_bindgen(js_name = anoncredsCreateCredentialDefinitionCustom)]
pub fn anoncreds_create_credential_definition_custom(
    schema_id: &str,
    schema: JsValue,
    tag: &str,
    issuer_id: &str,
) -> Vec<JsValue> {
    let schema: Schema = serde_wasm_bindgen::from_value(schema).unwrap();

    let (cred_def, cred_def_pvt, key_proof) = issuer::create_credential_definition(
        schema_id,
        &schema,
        issuer_id,
        tag,
        SignatureType::CL,
        CredentialDefinitionConfig { support_revocation: false },
    )
    .unwrap();

    let cred_def = serde_wasm_bindgen::to_value(&cred_def).unwrap();
    let cred_def_pvt = serde_wasm_bindgen::to_value(&cred_def_pvt).unwrap();
    let key_proof = serde_wasm_bindgen::to_value(&key_proof).unwrap();

    vec![cred_def, cred_def_pvt, key_proof]
}


#[wasm_bindgen(js_name = anoncredsValidateCredentialDefinitionFromJson)]
pub fn anoncreds_validate_credential_definition_from_json(
    json: JsValue
) -> Result<bool, JsValue> {
    let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(json).map_err(|e| <serde_wasm_bindgen::Error as Into<JsValue>>::into(e))?;
    cred_def.validate().map(|_| true).map_err(|e| JsValue::from_str(&e.to_string()))
}

// --- PROVER ---

#[wasm_bindgen(js_name = proverCreateLinkSecret)]
pub fn prover_create_link_secret() -> String {
  let secret = prover::create_link_secret().expect("Unable to create link secret");
  let secret_str = secret.try_into().expect("Unable to convert link secret");

  return secret_str;
}

#[wasm_bindgen(js_name = proverCreateCredentialRequest)]
pub fn prover_create_credential_request(
  cred_offer: JsValue,
  cred_def: JsValue,
  link_secret: &str,
  link_secret_id: &str
) -> Vec<JsValue> {
  let credential_offer = deserialise_credential_offer(cred_offer);
  let cred_def = deserialise_credential_definition(cred_def);
  let link_secret = deserialise_link_secret(link_secret);
  let entropy = new_nonce().unwrap().to_string();
  
  let (credential_request, credential_request_metadata) =
    prover::create_credential_request(
      Some(&entropy),
      None,
      &cred_def,
      &link_secret,
      &link_secret_id,
      &credential_offer,
    )
    .expect("Unable to create Credential Request");

  let js_cred_req = serde_wasm_bindgen::to_value(&credential_request).expect("Unable to serialise Credential Request");
  let js_cred_meta = serde_wasm_bindgen::to_value(&credential_request_metadata).expect("Unable to serialise Credential Request Metadata");
  let js_entropy = serde_wasm_bindgen::to_value(&entropy).expect("Unable to serialise Entropy");

  vec![js_cred_req, js_cred_meta, js_entropy]
}

#[wasm_bindgen(js_name = proverProcessCredential)]
pub fn prover_process_credential(
  cred_def: JsValue,
  credential: JsValue,
  cred_req_meta: JsValue,
  link_secret: &str,
) -> JsValue {
  let mut credential = deserialise_credential(credential);
  let cred_def = deserialise_credential_definition(cred_def);
  let cred_req_meta = deserialise_credential_request_metadata(cred_req_meta);
  let link_secret = deserialise_link_secret(link_secret);

  prover::process_credential(
    &mut credential,
    &cred_req_meta,
    &link_secret,
    &cred_def,
    None
  )
  .expect("Unable to process the Credential");

  serde_wasm_bindgen::to_value(&credential).expect("Unable to serialise Credential")
}

#[wasm_bindgen(js_name = proverCreatePresentation)]
pub fn prover_create_presentation(
  presentation_request: JsValue,
  schema_dict: JsValue,
  cred_def_dict: JsValue,
  credential: JsValue,
  link_secret: &str,
) -> JsValue {
  let pres_request = deserialise_presentation_request(presentation_request);
  let credential = deserialise_credential(credential);
  let link_secret = deserialise_link_secret(link_secret);

  let mut schemas = HashMap::new();
  let schema_list: HashMap<SchemaId, Schema> = serde_wasm_bindgen::from_value(schema_dict)
    .expect("Unable to deserialise Schemas");

  for (key, value) in schema_list.iter() {
    schemas.insert(key, value);
  }

  let mut cred_defs = HashMap::new();
  let cred_def_list: HashMap<CredentialDefinitionId, CredentialDefinition> = serde_wasm_bindgen::from_value(cred_def_dict)
    .expect("Unable to deserialise Credential Definitions");

  for (key, value) in cred_def_list.iter() {
    cred_defs.insert(key, value);
  }

  let mut present = PresentCredentials::default();
  let mut cred1 = present.add_credential(&credential, None, None);
  let pres_req_val = pres_request.value();

  for key in pres_req_val.requested_attributes.keys() {
    cred1.add_requested_attribute(key, true);
  }

  for key in pres_req_val.requested_predicates.keys() {
    cred1.add_requested_predicate(key);
  }

  let presentation = prover::create_presentation(
    &pres_request,
    present,
    None,
    &link_secret,
    &schemas,
    &cred_defs
  )
  .expect("Unable to create Presentation");

  serde_wasm_bindgen::to_value(&presentation).expect("Unable to serialise Presentation")
}

// --- SERDE ---

fn deserialise_credential(credential: JsValue) -> Credential {
  serde_wasm_bindgen::from_value(credential).expect("Unable to deserialise Credential")
}

fn deserialise_credential_offer(cred_offer: JsValue) -> CredentialOffer {
  serde_wasm_bindgen::from_value(cred_offer).expect("Unable to deserialise Credential Offer")
}

fn deserialise_credential_definition(cred_def: JsValue) -> CredentialDefinition {
  serde_wasm_bindgen::from_value(cred_def).expect("Unable to deserialise Credential Definition")
}

fn deserialise_credential_request_metadata(cred_req_meta: JsValue) -> CredentialRequestMetadata {
  serde_wasm_bindgen::from_value(cred_req_meta).expect("Unable to deserialise Credential Request Metadata")
}

fn deserialise_link_secret(link_secret: &str) -> LinkSecret {
  LinkSecret::try_from(link_secret).expect("Unable to deserialise Link Secret")
}

fn deserialise_presentation_request(pres_req: JsValue) -> PresentationRequest {
  let json = serde_wasm_bindgen::from_value(pres_req).expect("Unable to deserialise Presentation Request");
  serde_json::from_value(json).expect("Unable to parse Presentation Request")
}