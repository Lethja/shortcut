#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!("{}:{}; {}", file!(), line!(), format!($($arg)*));
    };
}
