use ed25519_dalek::{ Signature, Signer, SigningKey, Verifier, VerifyingKey };
use minicbor::{ Encode, Decode };

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct Object {
    
}