fn main() {
    hemtt_sign::execute("bisign", &std::env::args().collect::<Vec<_>>()).unwrap();
}
