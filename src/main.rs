use bisign::*;

fn main() {
    crate::execute(&std::env::args().collect::<Vec<_>>()).unwrap();
}