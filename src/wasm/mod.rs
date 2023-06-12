extern crate console_error_panic_hook;

use std::str::FromStr;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;
use wasm_logger;

use crate::utils::validation::Validatable;

// use crate::types::SignatureType;
use crate::data_types::credential::Credential;
use crate::data_types::cred_def::SignatureType;
use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionPrivate;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::cred_offer::CredentialOffer;
use crate::data_types::cred_request::CredentialRequest;
use crate::data_types::cred_request::CredentialRequestMetadata;
use crate::data_types::presentation::Presentation;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::link_secret::LinkSecret;

use crate::services::issuer;
use crate::services::prover;
use crate::services::verifier;

use crate::types::CredentialDefinitionConfig;
use crate::types::MakeCredentialValues;
use crate::types::PresentCredentials;

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


// --- ISSUER ---

#[wasm_bindgen(js_name = issuerCreateSchema)]
pub fn issuer_sample_schema() -> JsValue {
  let attribute_names: &[&str] = &["name", "age"];

  let schema = issuer::create_schema(
      "schema name",
      "1.0",
      "did:web:xyz",
      attribute_names.into()
  ).expect("Unable to create schema");

  return serde_wasm_bindgen::to_value(&schema).unwrap();
}

#[wasm_bindgen(js_name = issuerCreateCredentialOffer)]
pub fn issuer_create_credential_offer(jsSchema: JsValue) -> Vec<JsValue> {
    let schema: Schema = serde_wasm_bindgen::from_value(jsSchema).unwrap();

    let (cred_def, cred_def_priv, key_correctness_proof) =
        issuer::create_credential_definition("did:web:xyz/resource/schema",
                                            &schema,
                                            "did:web:xyz",
                                            "default-tag",
                                            SignatureType::CL,
                                            CredentialDefinitionConfig::default()
                                            ).expect("Unable to create Credential Definition");

    let credential_offer =
        issuer::create_credential_offer("did:web:xyz/resource/schema",
                                        "did:web:xyz/resource/cred-def",
                                        &key_correctness_proof,
                                        ).expect("Unable to create Credential Offer");

    let js_cred_offer = serde_wasm_bindgen::to_value(&credential_offer).unwrap();
    let js_cred_def = serde_wasm_bindgen::to_value(&cred_def).unwrap();
    let js_cred_def_priv = serde_wasm_bindgen::to_value(&cred_def_priv).unwrap();
    
    vec![js_cred_offer, js_cred_def, js_cred_def_priv]
}

#[wasm_bindgen(js_name = issuerCreateCredential)]
pub fn issuer_create_credential(
    jsCredOffer: JsValue,
    jsCredDef: JsValue,
    jsCredDefPriv: JsValue,
    jsCredRequest: JsValue
) -> JsValue {
    let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(jsCredDef).unwrap();
    let cred_def_priv: CredentialDefinitionPrivate = serde_wasm_bindgen::from_value(jsCredDefPriv).unwrap();
    let credential_offer: CredentialOffer = serde_wasm_bindgen::from_value(jsCredOffer).unwrap();
    let credential_request: CredentialRequest = serde_wasm_bindgen::from_value(jsCredRequest).unwrap();

    let mut credential_values = MakeCredentialValues::default();
    credential_values.add_raw("name", "john").expect("Unable to add credential value");
    credential_values.add_raw("age", "28").expect("Unable to add credential value");

    let credential =
        issuer::create_credential(
            &cred_def,
            &cred_def_priv,
            &credential_offer,
            &credential_request,
            credential_values.into(),
            None,
            None,
            None
        )
        .expect("Unable to create credential");

  trace!("createCredential > {:?}", credential);

  serde_wasm_bindgen::to_value(&credential).unwrap()
}


// --- PROVER ---

#[wasm_bindgen(js_name = proverCreateLinkSecret)]
pub fn prover_create_link_secret() -> String {
    let secret = prover::create_link_secret().expect("Unable to create link secret");
    let secretString = secret.try_into().expect("Unable to convert link secret");

    return secretString;
}

/**
 * 
 */
#[wasm_bindgen(js_name = proverCreateCredentialRequest)]
pub fn prover_create_credential_request(
  jsCredOffer: JsValue,
  jsCredDef: JsValue,
  jsLinkSecret: &str,
  jsLinkSecretId: &str
) -> Vec<JsValue> {
  let credential_offer: CredentialOffer = serde_wasm_bindgen::from_value(jsCredOffer.clone()).unwrap();
  let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(jsCredDef).unwrap();
  let link_secret = LinkSecret::try_from(jsLinkSecret).unwrap();
  let link_secret_id = jsLinkSecretId;
  
  let (credential_request, credential_request_metadata) =
  prover::create_credential_request(
    // TODO - guessing this should be randomised / seeded?
    Some("entropy"),
    // TODO - find out difference between using ProverDID or Entropy (one or other)
    None,
    &cred_def,
    &link_secret,
    &link_secret_id,
    &credential_offer,
  )
  .expect("Unable to create credential request");

  let js_cred_req = serde_wasm_bindgen::to_value(&credential_request).unwrap();
  let js_cred_meta = serde_wasm_bindgen::to_value(&credential_request_metadata).unwrap();

  vec![js_cred_req, js_cred_meta]
}

#[wasm_bindgen(js_name = proverProcessCredential)]
pub fn prover_process_credential(
  jsSchema: JsValue,
  jsCredDef: JsValue,
  jsCredential: JsValue,
  jsCredReqMeta: JsValue,
  jsLinkSecret: &str,
) -> JsValue {
  let mut credential: Credential = serde_wasm_bindgen::from_value(jsCredential).unwrap();
  let cred_req_meta: CredentialRequestMetadata = serde_wasm_bindgen::from_value(jsCredReqMeta).unwrap();
  let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(jsCredDef).unwrap();
  let link_secret = LinkSecret::try_from(jsLinkSecret).unwrap();

  prover::process_credential(
      &mut credential,
      &cred_req_meta,
      &link_secret,
      &cred_def,
      None
  )
  .expect("Unable to process the credential");

  serde_wasm_bindgen::to_value(&credential).unwrap()
}

#[wasm_bindgen(js_name = proverCreatePresentation)]
pub fn prover_create_presentation(
  jsPresentationRequest: JsValue,
  jsSchema: JsValue,
  jsCredDef: JsValue,
  jsProcessedCredential: JsValue,
  jsLinkSecret: &str,
) -> JsValue {
  let mut credential: Credential = serde_wasm_bindgen::from_value(jsProcessedCredential).unwrap();
  let schema: Schema = serde_wasm_bindgen::from_value(jsSchema).unwrap();
  let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(jsCredDef).unwrap();
  let link_secret = LinkSecret::try_from(jsLinkSecret).expect("convert error");
  let pres_request = serde_json::from_value(serde_wasm_bindgen::from_value(jsPresentationRequest).unwrap()).expect("Unable to create presentation request");
  let nonce = verifier::generate_nonce().expect("Unable to generate nonce");

  let mut schemas = HashMap::new();
  let schema_id = SchemaId::new_unchecked("did:web:xyz/resource/schema");
  schemas.insert(&schema_id, &schema);

  let mut cred_defs = HashMap::new();
  let cred_def_id = CredentialDefinitionId::new_unchecked("did:web:xyz/resource/cred-def");
  cred_defs.insert(&cred_def_id, &cred_def);

  let mut present = PresentCredentials::default();
  let mut cred1 = present.add_credential(
      &credential,
      None,
      None,
  );
  cred1.add_requested_attribute("attr1_referent", true);
  cred1.add_requested_predicate("predicate1_referent");

  let presentation =
      prover::create_presentation(&pres_request,
                                  present,
                                  None,
                                  &link_secret,
                                  &schemas,
                                  &cred_defs
                                  ).expect("Unable to create presentation");

  serde_wasm_bindgen::to_value(&presentation).unwrap()
}

#[wasm_bindgen(js_name = verifierGenerateNonce)]
pub fn verifier_generate_nonce() -> JsValue {
  let nonce = verifier::generate_nonce().unwrap();

  serde_wasm_bindgen::to_value(&nonce).unwrap()
}

#[wasm_bindgen(js_name = proverCreatePresentation_old)]
pub fn prover_create_presentation_old(
    jsSchema: JsValue,
    jsCredDef: JsValue,
    jsCredential: JsValue,
    jsCredReqMeta: JsValue,
    jsLinkSecret: &str,
) -> JsValue {
    let schema: Schema = serde_wasm_bindgen::from_value(jsSchema).unwrap();
    let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(jsCredDef).unwrap();
    let mut credential: Credential = serde_wasm_bindgen::from_value(jsCredential).unwrap();
    let cred_req_meta: CredentialRequestMetadata = serde_wasm_bindgen::from_value(jsCredReqMeta).unwrap();
    let link_secret = LinkSecret::try_from(jsLinkSecret).expect("convert error");

    prover::process_credential(
        &mut credential,
        &cred_req_meta,
        &link_secret,
        &cred_def,
        None
    )
    .expect("Unable to process the credential");

    let nonce = verifier::generate_nonce().expect("Unable to generate nonce");
    let pres_request = serde_json::from_value(serde_json::json!({
        "nonce": nonce,
        "name":"example_presentation_request",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": {
                    "cred_def_id": "did:web:xyz/resource/cred-def"
                }
            },
        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        }
    }))
    .expect("Unable to create presentation request");

    let mut schemas = HashMap::new();
    let schema_id = SchemaId::new_unchecked("did:web:xyz/resource/schema");
    schemas.insert(&schema_id, &schema);

    let mut cred_defs = HashMap::new();
    let cred_def_id = CredentialDefinitionId::new_unchecked("did:web:xyz/resource/cred-def");
    cred_defs.insert(&cred_def_id, &cred_def);

    let mut present = PresentCredentials::default();
    let mut cred1 = present.add_credential(
        &credential,
        None,
        None,
    );
    cred1.add_requested_attribute("attr1_referent", true);
    cred1.add_requested_predicate("predicate1_referent");

    let presentation =
        prover::create_presentation(&pres_request,
                                    present,
                                    None,
                                    &link_secret,
                                    &schemas,
                                    &cred_defs
                                    ).expect("Unable to create presentation");

    serde_wasm_bindgen::to_value(&presentation).unwrap()
}

// --- VERIFIER ---

#[wasm_bindgen(js_name = verifierVerifyPresentation)]
pub fn verifier_verify_presentation(
  jsPresentation: JsValue, 
  jsSchema: JsValue, 
  jsCredDef: JsValue
) -> bool {
  let presentation: Presentation = serde_wasm_bindgen::from_value(jsPresentation).unwrap();
  let nonce = verifier::generate_nonce().expect("Unable to generate nonce");
  let pres_request = serde_json::from_value(serde_json::json!({
    "nonce": nonce,
    "name":"example_presentation_request",
    "version":"0.1",
    "requested_attributes":{
        "attr1_referent":{
            "name":"name",
            "restrictions": {
                "cred_def_id": "did:web:xyz/resource/cred-def"
            }
        },
    },
    "requested_predicates":{
        "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
    }
  }))
  .expect("Unable to create presentation request");

  let schema: Schema = serde_wasm_bindgen::from_value(jsSchema).unwrap();
  let mut schemas = HashMap::new();
  let schema_id = SchemaId::new_unchecked("did:web:xyz/resource/schema");
  schemas.insert(&schema_id, &schema);

  let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(jsCredDef).unwrap();
  let mut cred_defs = HashMap::new();
  let cred_def_id = CredentialDefinitionId::new_unchecked("did:web:xyz/resource/cred-def");
  cred_defs.insert(&cred_def_id, &cred_def);

  let verified = verifier::verify_presentation(&presentation, &pres_request, &schemas, &cred_defs, None, None, None).expect("Error");

  return verified;
}

// run the full flow in rust
#[wasm_bindgen(js_name = exampleFull)]
pub fn example_full() {
  let attribute_names: &[&str] = &["name", "age"];
  let schema = issuer::create_schema("schema name",
                                    "1.0",
                                    "did:web:xyz",
                                    attribute_names.into()
                                    ).expect("Unable to create schema");

  let (cred_def, cred_def_priv, key_correctness_proof) =
      issuer::create_credential_definition("did:web:xyz/resource/schema",
                                          &schema,
                                          "did:web:xyz",
                                          "default-tag",
                                          SignatureType::CL,
                                          CredentialDefinitionConfig::default()
                                          ).expect("Unable to create Credential Definition");

  let credential_offer =
      issuer::create_credential_offer("did:web:xyz/resource/schema",
                                      "did:web:xyz/resource/cred-def",
                                      &key_correctness_proof,
                                      ).expect("Unable to create Credential Offer");

  //  let link_secret = prover::create_link_secret().expect("Unable to create link secret");
  let link_secret = LinkSecret::try_from("91993318581943239787710545985430259578940863873840022280074112605544397756609").expect("convert error");

  let (credential_request, credential_request_metadata) =
      prover::create_credential_request(Some("entropy"),
                                        None,
                                        &cred_def,
                                        &link_secret,
                                        "my-secret-id",
                                        &credential_offer,
                                        ).expect("Unable to create credential request");

  let mut credential_values = MakeCredentialValues::default();
  credential_values.add_raw("name", "john").expect("Unable to add credential value");
  credential_values.add_raw("age", "28").expect("Unable to add credential value");

  let mut credential =
      issuer::create_credential(&cred_def,
                                &cred_def_priv,
                                &credential_offer,
                                &credential_request,
                                credential_values.into(),
                                None,
                                None,
                                None
                                ).expect("Unable to create credential");

  prover::process_credential(&mut credential,
                            &credential_request_metadata,
                            &link_secret,
                            &cred_def,
                            None
                            ).expect("Unable to process the credential");

  let nonce = verifier::generate_nonce().expect("Unable to generate nonce");
  let pres_request = serde_json::from_value(serde_json::json!({
      "nonce": nonce,
      "name":"example_presentation_request",
      "version":"0.1",
      "requested_attributes":{
          "attr1_referent":{
              "name":"name",
              "restrictions": {
                  "cred_def_id": "did:web:xyz/resource/cred-def"
              }
          },
      },
      "requested_predicates":{
          "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
      }
  }))
  .expect("Unable to create presentation request");

  let mut schemas = HashMap::new();
  let schema_id = SchemaId::new_unchecked("did:web:xyz/resource/schema");
  schemas.insert(&schema_id, &schema);

  let mut cred_defs = HashMap::new();
  let cred_def_id = CredentialDefinitionId::new_unchecked("did:web:xyz/resource/cred-def");
  cred_defs.insert(&cred_def_id, &cred_def);

  let mut present = PresentCredentials::default();
  let mut cred1 = present.add_credential(
      &credential,
      None,
      None,
  );
  cred1.add_requested_attribute("attr1_referent", true);
  cred1.add_requested_predicate("predicate1_referent");

  let presentation =
      prover::create_presentation(&pres_request,
                                  present,
                                  None,
                                  &link_secret,
                                  &schemas,
                                  &cred_defs
                                  ).expect("Unable to create presentation");

  let verified = verifier::verify_presentation(&presentation, &pres_request, &schemas, &cred_defs, None, None, None);
}
