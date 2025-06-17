use uuid::Uuid;
use super::{email, password};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// A strongly-typed wrapper around a UUID for identifying `Account` entities.
///
/// This type enforces type safety by distinguishing account identifiers from other UUID-based IDs,
/// such as those for roles or profiles, even though they share the same underlying UUID type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountID(Uuid);
impl AccountID {
    /// Creates a new `AccountID` with a randomly generated UUID (UUID v4).
    ///
    /// # Example
    ///
    /// ```
    /// let id = AccountID::new();
    /// ```
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Constructs an `AccountID` from an existing `Uuid`.
    ///
    /// Useful when you already have a UUID (e.g., from a database) and want to wrap it as an `AccountID`.
    ///
    /// # Arguments
    ///
    /// * `uuid` - A `Uuid` instance to wrap.
    ///
    /// # Example
    ///
    /// ```
    /// let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    /// let id = AccountID::from_uuid(uuid);
    /// ```
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns a reference to the inner `Uuid`.
    ///
    /// # Example
    ///
    /// ```
    /// let id = AccountID::new();
    /// let uuid_ref = id.as_uuid();
    /// ```
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

/// Represents the role associated with an account.
/// 
/// Common roles include:
/// - `Admin`: Typically has elevated permissions or system-level access.
/// - `User`: Standard user access.
///
/// This enum supports (de)serialization using `serde`, with string values
/// `"admin"` and `"user"` respectively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    User,
}

impl AccountRole {    
    /// Attempts to create an `AccountRole` from a string slice.
    ///
    /// # Parameters
    /// - `text`: A string representing the role.
    ///
    /// # Returns
    /// - `Ok(AccountRole::Admin)` if `text` equals `"admin"`.
    /// - `Ok(AccountRole::User)` if `text` equals `"user"`.
    /// - `Err(String)` if the role is unrecognized.
    ///
    /// # Examples
    /// ```
    /// let role = AccountRole::from_str("admin").unwrap();
    /// assert_eq!(role, AccountRole::Admin);
    /// ```
    pub fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "admin" => Ok(AccountRole::Admin),
            "user" => Ok(AccountRole::User),
            _ => Err(format!("Invalid account role: {}", text))
        }
    }
}

/// Represents the current status of an account.
///
/// Typical lifecycle states are:
/// - `Active`: Account is available and usable.
/// - `Deleted`: Account has been marked as removed or deactivated.
///
/// This enum is serializable using `serde` with string values `"active"` and `"deleted"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "deleted")]
    Deleted,
}

impl AccountStatus {
    /// Creates an `AccountStatus` from a string slice.
    ///
    /// # Parameters
    /// - `text`: A string indicating the account status.
    ///
    /// # Returns
    /// - `AccountStatus::Active` if `text` is `"active"`.
    /// - `AccountStatus::Deleted` for any other value.
    /// - `Err(String)` if the status is unrecognized.
    ///
    /// # Examples
    /// ```
    /// let status = AccountStatus::from_str("deleted");
    /// assert_eq!(status, AccountStatus::Deleted);
    /// ```
    pub fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "active" => Ok(AccountStatus::Active),
            "deleted" => Ok(AccountStatus::Deleted),
            _ => Err(format!("Invalid account status: {}", text))
        }
    }
}

/// Represents a user account in the system.
///
/// Each account has a unique identifier, an associated email address, a role,
/// and a status. Optionally, an account may contain a password hash if a password
/// has been set. The timestamps `created_at` and `updated_at` record when the
/// account was created and last modified.
///
/// The password hash is not serialized when the struct is converted to formats
/// like JSON to prevent leaking sensitive data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    _id: AccountID,
    email: email::Email,
    #[serde(skip_serializing)]
    hash: Option<password::Hash>,
    role: AccountRole,
    status: AccountStatus,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Defines possible errors when working with an `Account`.
#[derive(Debug)]
pub enum AccountError {
    /// Password hashing failed during the password set operation.
    PasswordHashingFailed,
    /// No password hash was set, so password verification is not possible.
    PasswordNotSet,
    /// Password verification failed (wrong password).
    InvalidPassword,
}

impl Account {
    /// Creates a new `Account` instance with the given email.
    ///
    /// The account will be assigned a new UUID, have `User` role and `Active` status
    /// by default, and will not have a password set. Timestamps are initialized to the
    /// current UTC time.
    ///
    /// # Parameters
    /// - `email`: The email address to associate with the new account.
    ///
    /// # Returns
    /// A new `Account` instance.
    pub fn new(email: email::Email) -> Self {
        let utc_now = Utc::now();
        Account {
            _id: AccountID::new(),
            email,
            hash: None,
            role: AccountRole::User,
            status: AccountStatus::Active,
            created_at: utc_now,
            updated_at: utc_now,
        }
    }

    /// Sets the password for the account by hashing it with the provided key.
    ///
    /// This function clones the current account and returns a new account instance
    /// with the password hash set.
    ///
    /// # Parameters
    /// - `hashing_key`: A key used by the hashing algorithm.
    /// - `password`: The plaintext password to be hashed and stored.
    ///
    /// # Returns
    /// - `Ok(Account)` with the updated password hash if hashing succeeds.
    /// - `Err(AccountError::PasswordHashingFailed)` if hashing fails.
    pub fn set_password(&mut self, hashing_key: &str, password: &password::Password) -> Result<(), AccountError> {
        match password::Hash::from_password(hashing_key, password) {
            Ok(hash) => {
                self.hash = Some(hash);
                Ok(())
            },
            Err(_) => {
                Err(AccountError::PasswordHashingFailed)
            }
        }
    }

    /// Verifies whether the provided password matches the stored password hash.
    ///
    /// # Parameters
    /// - `password`: The plaintext password to verify.
    ///
    /// # Returns
    /// - `Ok(())` if the password is correct.
    /// - `Err(AccountError::PasswordNotSet)` if no password has been set.
    /// - `Err(AccountError::InvalidPassword)` if the password is incorrect.
    pub fn verify_password(&self, password: &password::Password) -> Result<(), AccountError> {
        let hash = self.hash.as_ref().ok_or(AccountError::PasswordNotSet)?;
        hash.verify_password(password)
            .map_err(|_| AccountError::InvalidPassword)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    macro_rules! account_password_test_cases {
        (
            $(
                ($test_name: ident, $set_password: expr, $test_password: expr, $is_error: expr)
            ),*
        ) => {
            $(
                #[test]
                fn $test_name() {
                    let set_password = password::Password::new($set_password)
                        .expect("Failed to create set_password");
                    
                    let mut account = Account::new(email::Email::new("xxx@xxx.xxx").unwrap());
                    
                    let key: &str = &password::generate_sha512_crypt_salt(100, Some(16));
                    
                    account.set_password(key, &set_password)
                        .expect("Failed to set password");
                    
                    let test_password = password::Password::new($test_password)
                        .expect("Failed to create test_password");

                    assert_eq!(
                        account.verify_password(&test_password).is_err(),
                        $is_error
                    );
                }
            )*
        };
    }

    account_password_test_cases! {
        (different_password, "Password123!",  "Password1234!", true),
        (matched_password, "Password123!",  "Password123!", false)
    }
}