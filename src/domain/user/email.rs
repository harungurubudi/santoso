use serde::{Deserialize, Serialize};
use std::fmt;
use validator::Validate;

/// Represents a validated email address as a value object.
///
/// This struct ensures that the contained email string is valid according to standard
/// email formatting rules, as enforced by the `validator` crate.
///
/// Validation is performed via the `#[validate(email)]` attribute on the inner value field.
/// Instances should be created using the [`Email::new`] constructor to ensure validity.
///
/// # Fields
///
/// * `value` - A string containing the validated email address.
///
/// # Examples
///
/// ```
/// use your_crate::Email; // Adjust import path as needed
///
/// let email = Email::new("user@example.com".to_string());
/// assert!(email.is_ok());
/// ```
#[derive(Validate, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Email {
    #[validate(email)]
    value: String,
}

impl Email {
    /// Creates a new `Email` instance after validating the input string.
    ///
    /// # Arguments
    ///
    /// * `value` - A `&str` representing the email address to be validated.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` if the email is valid according to the `#[validate(email)]` rule.
    /// * `Err(validator::ValidationErrors)` if the validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use your_crate::Email; // Adjust import based on your module structure
    ///
    /// let email = Email::new("user@example.com".to_string());
    /// assert!(email.is_ok());
    /// ```
    pub fn new(value: &str) -> Result<Self, validator::ValidationErrors> {
        let email: Email= Self{value: String::from(value)};
        email.validate()?; // Perform validation here
        Ok(email)
    }
}

impl fmt::Debug for Email {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Email")
            .field("value", &self.value)
            .finish()
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl From<Email> for String {
    fn from(email: Email) -> Self {
        email.value
    }
}
impl TryFrom<String> for Email {
    type Error = validator::ValidationErrors;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let email: Email = Self{value};
        email.validate()?;
        Ok(email)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    macro_rules! email_test{
        (
            $(
                ($test_name: ident, $input_text: expr, $is_valid: expr)
            ),*
        ) => {
            $(
                #[test]
                fn $test_name() {
                    let email = Email::new($input_text);
                    assert_eq!(email.is_err(), !$is_valid)
                }
            )*
        };
    }

    email_test! {
        (invalid_email_test, "harunasolole", false),
        (valid_email_test, "harunsadja@gmail.com", true)
    }
}