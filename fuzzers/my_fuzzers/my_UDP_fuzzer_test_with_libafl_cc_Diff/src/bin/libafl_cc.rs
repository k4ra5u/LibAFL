use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, ToolWrapper};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        dir.pop();

        let mut cc = ClangWrapper::new();
        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            // Enable libafl's coverage instrumentation
            .add_arg("-fsanitize-coverage=trace-pc-guard")
            // Imitate afl-cc's compile definitions 
            .add_arg("-D__AFL_FUZZ_INIT()=void libafl_start_forkserver(void)")

            .add_arg("-D__AFL_INIT()=libafl_start_forkserver()")
            // Link with libafl's forkserver implementation
            .link_staticlib(&dir, "libafl_cc")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
