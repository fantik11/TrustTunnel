use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};


pub(crate) const SHA1_DIGEST_SIZE: usize = 20;


pub fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .fold(
            String::with_capacity(2 * buf.len()),
            |str, b| str + format!("{:02x}", b).as_str()
        )
}

pub fn hex_dump_uppercase(buf: &[u8]) -> String {
    buf.iter()
        .fold(
            String::with_capacity(2 * buf.len()),
            |str, b| str + format!("{:02X}", b).as_str()
        )
}

/// Can hold either of the options
pub(crate) enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> Either<L, R> {
    pub fn with_left(l: L) -> Self {
        Self::Left(l)
    }

    pub fn with_right(r: R) -> Self {
        Self::Right(r)
    }

    /// Apply the function to the object in case it contains the [`Self::Left`] option.
    /// Otherwise, do nothing.
    pub fn map_left<F, T>(self, f: F) -> Either<T, R>
        where F: FnOnce(L) -> T,
    {
        match self {
            Self::Left(x) => Either::<T, R>::Left(f(x)),
            Self::Right(x) => Either::<T, R>::Right(x),
        }
    }

    /// Apply the function to the object in case it contains the [`Self::Right`] option.
    /// Otherwise, do nothing.
    pub fn map_right<F, T>(self, f: F) -> Either<L, T>
        where F: FnOnce(R) -> T,
    {
        match self {
            Self::Left(x) => Either::<L, T>::Left(x),
            Self::Right(x) => Either::<L, T>::Right(f(x)),
        }
    }

    /// Apply the functions to the object accordingly to a contained option.
    pub fn map<FL, FR, T>(self, left: FL, right: FR) -> T
    where
        FL: FnOnce(L) -> T,
        FR: FnOnce(R) -> T,
    {
        match self {
            Self::Left(x) => left(x),
            Self::Right(x) => right(x),
        }
    }
}

pub(crate) fn load_certs(filename: &str) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(filename)?))
        .map_err(|e| io::Error::new(
            ErrorKind::InvalidInput, format!("Invalid cert: {}", e)))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

pub(crate) fn load_private_key(filename: &str) -> io::Result<PrivateKey> {
    pkcs8_private_keys(&mut BufReader::new(File::open(filename)?))
        .map_err(|e| io::Error::new(
            ErrorKind::InvalidInput, format!("Invalid key: {}", e)))
        .map(|mut keys| PrivateKey(keys.remove(0)))
}
