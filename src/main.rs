use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use ml_dsa::{SigningKey, MlDsa65};
use std::fs::File;
use std::io::{self, Read, Write};
use ml_dsa::signature::Signer;

#[cfg(test)]
mod tests;

/// Programa para convertir una firma base64 a una clave ML-DSA
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Firma en formato base64
    #[clap(long)]
    sign: String,

    /// Archivo JSON a procesar
    #[clap(long)]
    file: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut file = File::open(&args.file)?;
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)?;

    // Decodificar la firma en base64
    let signing_key_bytes = match STANDARD.decode(&args.sign) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error al decodificar la firma base64: {}", e);
            return Ok(());
        }
    };

    // Convertir los bytes a una clave de firma ML-DSA
    let signing_key = match convert_to_signing_key(&signing_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error al convertir a clave ML-DSA: {}", e);
            return Ok(());
        }
    };

    let sig = signing_key.sign(file_contents.as_ref());
    let sig_bytes = sig.encode();

    let mut file = File::create("sign.sig")?;
    file.write_all(&sig_bytes)?;
    println!("Firma guardada en sign.sig");
    Ok(())
}

fn convert_to_signing_key(bytes: &[u8]) -> Result<SigningKey<MlDsa65>, &'static str> {
    // Asumiendo que los bytes tienen el tamaño correcto para una clave MlDsa65
    if bytes.len() != std::mem::size_of::<ml_dsa::EncodedSigningKey<MlDsa65>>() {
        return Err("Tamaño de clave incorrecto");
    }

    // Crear una EncodedSigningKey vacía
    let mut encoded_key: ml_dsa::EncodedSigningKey<MlDsa65> = Default::default();

    // Copiar los bytes a la EncodedSigningKey
    encoded_key.copy_from_slice(bytes);

    // Decodificar la clave de firma
    Ok(SigningKey::<MlDsa65>::decode(&encoded_key))
}