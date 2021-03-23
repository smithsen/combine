use ff::PrimeField;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use rand::rngs::OsRng;
use ff::Field;
use bls12_381::{Bls12, Scalar};
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof,
};
use std::time::{Duration,Instant};
use pairing::Engine;



//size of the array
const LEN: usize = 2;
const null: u8 = 0;


//The base circuit, we have 3 input wires, document is private, redactor and redacted are public
struct RedactDemo<S: PrimeField>{
	document: Option<[S; LEN]>,
	redactor: Option<[S; LEN]>,
	redacted: Option<[S; LEN]>,
}

//Generating and comparing zero knowledge proof system


fn main(){
	
	//Parameter Generation
	println!("Generating Paramters...");
	let params = {
			let c = RedactDemo{
				document: None,
				redactor: None,
				redacted: None,						
				};
		     generate_random_parameters::<Bls12,_,_>(c,&mut OsRng).unwrap()
		    };
	//Generation verification keys
	let pvk = prepare_verifying_key(&params.vk);
	



	//Here document inputs as u8 elements
	let d_prior: [u8;LEN] = [20;LEN];
	
	
	//document values converted to field elements
	let mut document: [Scalar;LEN] = [convert_u8(null);LEN];
	for i in 1..LEN{
		document[i] = convert_u8(d_prior[i]);	
	}
	
	
	//Here redact inputs are u8 elements
	let redact_prior: [u8;LEN] = [1,0];
	
	//redact inputs converted to field elements
	let mut redactor: [Scalar;LEN] = [convert_u8(null); LEN];
	for i in 1..LEN{
		redactor[i] = convert_u8(redact_prior[i]);
	}

	//Here the public input the final redaction is created
	let mut final_prior: [u8; LEN] = [0; LEN];
	final_prior = redact(&d_prior, &redact_prior);
	
	//Convert the public input to field elements
	let mut redacted: [Scalar; LEN] = [convert_u8(null); LEN];
	for i in 1..LEN{
		redacted[i] = convert_u8(final_prior[i]);
	}
	


	for i in 1..LEN{
		println!("At level {}, {:?}, {:?},{:?}",i, document[i], redactor[i], redacted[i]);
	}

	//Creating witness with given inputs

	let c = RedactDemo{
		document: Some(document),
		redactor: Some(redactor),
		redacted: Some(redacted),
	};


	//Creating proof
	println!("Creating Proof Elements..");
    	let proof = create_random_proof(c, &params, &mut OsRng).unwrap();


	println!("First element: {:?}",proof.a);
	println!("Second element: {:?}",proof.b);
	println!("Third element: {:?}",proof.c);

	//Verifying proof
    	println!("Verifying...");
    	assert!(verify_proof(&pvk,&proof,&redacted).is_ok());
	
}


//convert u8 to field elements
fn convert_u8<S: ff::PrimeField>(x: u8) -> S {
    S::from(u64::from(x))
}

//array redaction function: pointwise dot product eg:- [20,20]*[1,0] = [20,0]
fn redact(preimage: &[u8], mask: &[u8]) -> [u8; LEN]{
	let mut internal = [0;LEN];
	for i in 1..LEN{
		internal[i] = preimage[i]*mask[i];
	}
return internal;
}


//Implementation of the circuit RedactDemo
impl <S> Circuit<S> for RedactDemo<S>
where 
	S : PrimeField,
{
//synthesize the circuit
   fn synthesize<CS: ConstraintSystem<S>>(self, cs: &mut CS) -> Result<(), SynthesisError>
   {
	//allocate private variable document and generating constraints corresponding to it
	let document_value = self.document;
	let document = cs.alloc(|| "document",|| document_value.ok_or(SynthesisError::AssignmentMissing))?;
	
	//allocate public variable redactor and generating constraints corresponding to it
	let redactor_value = self.redactor;
	let redactor = cs.alloc_input(|| "redactor", || redactor_value.ok_or(SynthesisError::AssignmentMissing))?;
	
	//allocate public variable redacted and generating constraints corresponding to it
	let redacted_value = self.redacted;
	let redacted = cs.alloc_input(|| "redacted", || redacted_value.ok_or(SynthesisError::AssignmentMissing))?;	

	//enforcing the constraints
	cs.enforce(
            			|| "mult",
            			|lc| lc + document,
            			|lc| lc + redactor,
            			|lc| lc + redacted
        		  );
	Ok(())
   }
}








