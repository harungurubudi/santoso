use validator::{Validate, ValidationError};
use serde::Deserialize;
use std::fmt;
use pwhash::sha512_crypt;

/// Represents a user's password as a value object.
///
/// This struct encapsulates a password string and ensures that it meets
/// defined security requirements through validation rules. The password must:
///
/// - Be between 8 and 18 characters long
/// - Contain at least one uppercase letter
/// - Contain at least one lowercase letter
/// - Contain at least one numeric digit
/// - Contain at least one special ASCII character
///
/// Validation is performed using the `validator` crate. The only way to create
/// a valid `Password` is through the `Password::new()` constructor, which applies
/// these constraints.
///
/// # Example
///
/// ```
/// let password = Password::new("StrongPass1@");
/// assert!(password.is_ok());
/// ```
#[derive(Validate, PartialEq, Eq, Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct Password {
    #[validate(length(min = 8, max = 18), custom(function = "validate_pass"))]
    value: String,
}

/// Validates the strength of a password string.
///
/// This function is used as a custom validator for the `Password` value object.
/// It ensures that the password contains at least one lowercase letter,
/// one uppercase letter, one numeric digit, and one special ASCII character.
///
/// # Parameters
///
/// - `passw`: A reference to the password string to validate.
///
/// # Returns
///
/// - `Ok(())` if the password meets all required criteria.
/// - `Err(ValidationError)` with the code `"weak_password"` and a human-friendly message
///   if the password is considered too weak.
///
/// # Example
///
/// ```
/// let result = validate_pass(&"StrongPass1@".to_string());
/// assert!(result.is_ok());
///
/// let weak = validate_pass(&"weakpass".to_string());
/// assert!(weak.is_err());
/// ```
fn validate_pass(passw: &String) -> Result<(), ValidationError> {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_number = false;
    let mut has_special = false;

    for c in passw.chars() {
        if c.is_ascii() {
            if c.is_alphabetic() {
                if c.is_lowercase() {
                    has_lower = true;
                } else if c.is_uppercase() {
                    has_upper = true;
                }
            } else if c.is_numeric() {
                has_number = true;
            } else {
                has_special = true;
            }
        }
    }

    if !(has_lower && has_upper && has_number && has_special) {
        let mut error: ValidationError = ValidationError::new("weak_password");
        error.message = Some("Password must contain upper, lower, number, and special char".into());
        return Err(error)
    }

    Ok(())
}

impl Password {
    pub fn new(value: &str) -> Result<Self, validator::ValidationErrors> {
        let password: Password = Self{value: String::from(value)};
        password.validate()?;
        Ok(password)
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Password")
            .field("value", &self.value)
            .finish()
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl TryFrom<String> for Password {
    type Error = validator::ValidationErrors;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let password: Password = Self{value};
        password.validate()?;
        Ok(password)
    }
}

#[derive(Clone, PartialEq)]
pub struct Hash {
    hash: String,
}

#[derive(Debug, Clone)]
pub struct HashingError;
impl std::error::Error for HashingError {}
impl fmt::Display for HashingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Failed to create hash from password")
    }
}

#[derive(Debug, Clone)]
pub struct PasswordVerifyError;
impl std::error::Error for PasswordVerifyError {}
impl fmt::Display for PasswordVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid password")
    }
}

impl Hash {
    pub fn from_password(key: &str, password: &Password) -> Result<Hash, HashingError> {
        match sha512_crypt::hash_with(key, password.to_string()) {
            Ok(result) => Ok(Hash { hash: result }),
            Err(_) => Err(HashingError {}),
        }
    }

    pub fn verify_password(&self, password: &Password) -> Result<(), PasswordVerifyError> {
        if self.hash.is_empty() {
            return Err(PasswordVerifyError);
        }
    
        if !sha512_crypt::verify(password.as_str(), &self.hash) {
            return Err(PasswordVerifyError);
        }
    
        Ok(())
    }
}

impl From<&str> for Hash {
    fn from(hash: &str) -> Self {
        Hash {
            hash: hash.to_string(),
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_password_verify_with_empty_hash() {
        let plain_text: Password = Password::new("Asolole123!").unwrap();
        let cipher_text: Hash = Hash::from("");
        assert!(cipher_text.verify_password(&plain_text).is_err());
    }

    #[test]
    fn test_password_verify_with_invalid_password() {
        let plain_text: Password = Password::new("Asolole123!").unwrap();
        let cipher_text: Hash = Hash::from("DifferentPassword123!");
        assert!(cipher_text.verify_password(&plain_text).is_err());
    }

    #[test]
    fn test_password_verify_with_valid_password() {
        let plain_text: Password = Password::new("Asolole123!").unwrap();
        let key: &str ="$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJURCXk43.EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/";
        let cipher_text: Hash = Hash::from_password(key, &plain_text).unwrap();
        let result = cipher_text.verify_password(&plain_text);
        assert!(result.is_ok());
    }

    macro_rules! password_validation_test_cases {
        (
            $(
                ($test_name: ident, $password: expr, $is_error: expr)
            ),*
        ) => {
            $(
                #[test]
                fn $test_name() {
                    let password_str: &str = $password;
                    assert_eq!(
                        $is_error, 
                        Password::new(password_str).is_err(),
                        "Password validation for '{}' did not match expectation (expected error: {})",
                        password_str,
                        $is_error
                    )
                }
            )*
        };
    }

    password_validation_test_cases! {
        (too_short_password_test, "mypass", true),
        (lowercase_only_password_test, "mypassword", true),
        (lower_and_upper_case_only_password_test, "MypassworD", true),
        (no_special_char_password_test, "MypassworD1234", true),
        (good_password_test, "MypassworD1234!", false)
    }
}