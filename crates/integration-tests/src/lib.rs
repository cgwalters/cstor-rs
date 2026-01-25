//! Integration test framework for cstor-rs.
//!
//! This crate provides infrastructure for running integration tests that require
//! isolated containers-storage instances. Tests are registered using the linkme
//! crate for distributed test registration.

#![allow(unsafe_code)] // Required for linkme

use libtest_mimic::{Arguments, Trial};
use linkme::distributed_slice;

pub mod fixture;
mod tests;

/// A distributed slice of integration tests, populated by the `integration_test!` macro.
#[distributed_slice]
pub static INTEGRATION_TESTS: [fn() -> Trial];

/// Run all registered integration tests.
pub fn run_tests() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args = Arguments::from_args();
    let tests: Vec<Trial> = INTEGRATION_TESTS.iter().map(|f| f()).collect();

    let conclusion = libtest_mimic::run(&args, tests);
    conclusion.exit();
}

/// Register an integration test function.
///
/// # Example
///
/// ```ignore
/// use integration_tests::{integration_test, fixture::TestStorage};
///
/// integration_test!(test_layer_creation, || {
///     let storage = TestStorage::new()?;
///     // ... test code
///     Ok(())
/// });
/// ```
#[macro_export]
macro_rules! integration_test {
    ($name:ident, $body:expr) => {
        $crate::paste::paste! {
            #[$crate::linkme::distributed_slice($crate::INTEGRATION_TESTS)]
            #[linkme(crate = $crate::linkme)]
            fn [<__register_ $name>]() -> $crate::libtest_mimic::Trial {
                $crate::libtest_mimic::Trial::test(
                    stringify!($name),
                    move || {
                        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = $body();
                        result.map_err(|e| $crate::libtest_mimic::Failed::from(e.to_string()))
                    },
                )
            }
        }
    };
}

// Re-export for use in macro
pub use libtest_mimic;
pub use linkme;
pub use paste;
