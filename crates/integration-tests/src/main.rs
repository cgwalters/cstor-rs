//! Integration test runner.

fn main() {
    integration_tests::run_tests().expect("test runner failed");
}
