use rand::rngs::OsRng;
use rsa::{BigUint, PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use std::io::BufRead;

fn main() {
    let mut args = std::env::args().skip(1);
    let action = args.next();

    match action.as_deref() {
        Some("e" | "enc" | "encrypt") => encrypt(args.next()),
        Some("d" | "dec" | "decrypt") => decrypt(),
        _ => print_help(),
    }
}

fn print_help() {
    println!(
        r#"
sm ...
Send Message utility: use RSA to send secure messages

USAGE:
        sm decrypt                  (aliases: d, dec)
    Generates a public RSA key to send to your friend. Enter lines in to
    decrypt what your friend sends.

        sm encrypt <PUBLIC_KEY>     (aliases: e, enc)
    Encrypts messages using the RSA key provided by your friend. Enter lines
    in to encrypt them.
"#
    );
}

fn encrypt(public_key: Option<String>) {
    let public_key = public_key.expect("expected argument to be passed in for public key!");
    let public_key = decode_pub_key(public_key);

    eprintln!("public key decoded! type a line to encrypt it");

    let mut rng = OsRng;
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock().lines();

    loop {
        let line = stdin
            .next()
            .expect("expected there to be data!")
            .expect("expected to read line!");

        let encrypted_data = public_key
            .encrypt(
                &mut rng,
                PaddingScheme::new_pkcs1v15_encrypt(),
                line.as_bytes(),
            )
            .expect("expected to encrypt data!");

        println!("{}", hex::encode_upper(encrypted_data));
    }
}

fn decrypt() {
    eprintln!("generating RSA private key...");

    let mut rng = OsRng;
    let bits = 2048;
    let private_key =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate RSA private key");
    eprintln!("computing public key...");
    let public_key = RsaPublicKey::from(&private_key);

    eprintln!("RSA public key:");
    println!("{}", encode_pub_key(&public_key));

    eprintln!("decryption prepared! send your friend the RSA public key!");
    eprintln!("then, paste in their encrypted messages here to decrypt them!");

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock().lines();

    loop {
        let line = stdin
            .next()
            .expect("expected there to be data!")
            .expect("expected to read line!");

        let encrypted_data = hex::decode(line).expect("expected to decode hex");
        let decrypted_data = private_key
            .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &encrypted_data)
            .expect("expected to decrypt!");

        match String::from_utf8(decrypted_data) {
            Ok(s) => println!("{s}"),
            Err(err) => println!("{:02X?}", err.into_bytes()),
        };
    }
}

fn encode_pub_key(public_key: &impl PublicKeyParts) -> String {
    let n = public_key.n().to_bytes_le();
    let e = public_key.e().to_bytes_le();

    let n_len = (n.len() as u64).to_le_bytes();

    let mut public_key_transmission = Vec::with_capacity(n_len.len() + n.len() + e.len());

    public_key_transmission.extend(n_len);
    public_key_transmission.extend(n);
    public_key_transmission.extend(e);

    hex::encode_upper(public_key_transmission)
}

fn decode_pub_key(key: String) -> RsaPublicKey {
    let mut bytes = hex::decode(key).expect("expected valid hex!");

    let u64_slice = bytes
        .splice(0..std::mem::size_of::<u64>(), [])
        .collect::<Vec<_>>();

    let u64_slice_exact = u64_slice.try_into().expect("expected to read u64!");
    let n_len = u64::from_le_bytes(u64_slice_exact) as usize;

    let n = bytes.splice(0..n_len, []).collect::<Vec<_>>();
    let e = bytes;

    let n = BigUint::from_bytes_le(n.as_slice());
    let e = BigUint::from_bytes_le(e.as_slice());
    RsaPublicKey::new(n, e).expect("expected to deserialize public key")
}
