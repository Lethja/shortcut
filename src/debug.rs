#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!("{}:{}\n{}\n", file!(), line!(), format!($($arg)*));
    };
}
