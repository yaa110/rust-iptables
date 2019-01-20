extern crate nix;
extern crate regex;

use std::{convert, error, fmt, io, num};

/// Defines the general error type of iptables crate
#[derive(Debug)]
pub enum IPTError {
    Io(io::Error),
    Regex(regex::Error),
    Nix(nix::Error),
    Parse(num::ParseIntError),
    BadExitStatus(i32),
    Other(&'static str),
}

/// Defines the Result type of iptables crate
pub type IPTResult<T> = Result<T, IPTError>;

impl fmt::Display for IPTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IPTError::Io(ref err) => write!(f, "{}", err),
            IPTError::Regex(ref err) => write!(f, "{}", err),
            IPTError::Nix(ref err) => write!(f, "{}", err),
            IPTError::Parse(ref err) => write!(f, "{}", err),
            IPTError::BadExitStatus(i) => write!(f, "{}", i),
            IPTError::Other(ref message) => write!(f, "{}", message),
        }
    }
}

impl error::Error for IPTError {
    fn description(&self) -> &str {
        match *self {
            IPTError::Io(ref err) => err.description(),
            IPTError::Regex(ref err) => err.description(),
            IPTError::Nix(ref err) => err.description(),
            IPTError::Parse(ref err) => err.description(),
            IPTError::BadExitStatus(_) => "iptables exited with a non-zero status.",
            IPTError::Other(ref message) => message,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            IPTError::Io(ref err) => Some(err),
            IPTError::Regex(ref err) => Some(err),
            IPTError::Nix(ref err) => Some(err),
            IPTError::Parse(ref err) => Some(err),
            _ => Some(self),
        }
    }
}

impl convert::From<io::Error> for IPTError {
    fn from(err: io::Error) -> Self {
        IPTError::Io(err)
    }
}

impl convert::From<regex::Error> for IPTError {
    fn from(err: regex::Error) -> Self {
        IPTError::Regex(err)
    }
}

impl convert::From<nix::Error> for IPTError {
    fn from(err: nix::Error) -> Self {
        IPTError::Nix(err)
    }
}

impl convert::From<num::ParseIntError> for IPTError {
    fn from(err: num::ParseIntError) -> Self {
        IPTError::Parse(err)
    }
}

impl convert::From<&'static str> for IPTError {
    fn from(err: &'static str) -> Self {
        IPTError::Other(err)
    }
}
