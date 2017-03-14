extern crate getopts;
use getopts::Options;
use std::env;


fn usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    println!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help");
    opts.optflag("V", "version", "Print version");
    opts.optopt("", "args", "Parse nul-separated args from FD", "FD");
    opts.optflag("", "unshare-all", "Unshare every namespace we support by default");
    opts.optflag("", "share-net", "Retain the network namespace (can only combine with --unshare-all)");
    opts.optflag("", "unshare-user", "Create new user namespace (may be automatically implied if not setuid)");
    opts.optflag("", "unshare-user-try", "Create new user namespace if possible else continue by skipping it");
    opts.optflag("", "unshare-ipc", "Create new ipc namespace");
    opts.optflag("", "unshare-pid", "Create new pid namespace");
    opts.optflag("", "unshare-net", "Create new network namespace");
    opts.optflag("", "unshare-uts", "Create new uts namespace");
    opts.optflag("", "unshare-cgroup", "Create new cgroup namespace");
    opts.optflag("", "unshare-cgroup-try", "Create new cgroup namespace if possible else continue by skipping it");
    opts.optopt("", "uid", "Custom uid in the sandbox (requires --unshare-user)", "UID");
    opts.optopt("", "gid", "Custon gid in the sandbox (requires --unshare-user)", "GID");
    opts.optopt("", "hostname", "Custom hostname in the sandbox (requires --unshare-uts)", "NAME");
    opts.optopt("", "chdir", "Change directory to DIR", "DIR");
    opts.optopt("", "setenv", "VALUE           Set an environment variable", "VAR");
    opts.optopt("", "unsetenv", "Unset an environment variable", "VAR");
    opts.optopt("", "lock-file", "Take a lock on DEST while sandbox is running", "DEST");
    opts.optopt("", "sync-fd", "Keep this fd open while sandbox is running", "FD");
    opts.optopt("", "bind", "DEST              Bind mount the host path SRC on DEST", "SRC");
    opts.optopt("", "dev-bind", "DEST          Bind mount the host path SRC on DEST, allowing device access", "SRC");
    opts.optopt("", "ro-bind", "DEST           Bind mount the host path SRC readonly on DEST", "SRC");
    opts.optopt("", "remount-ro", "Remount DEST as readonly, it doesn't recursively remount", "DEST");
    opts.optopt("", "exec-label", "Exec Label for the sandbox", "LABEL");
    opts.optopt("", "file-label", "File label for temporary sandbox content", "LABEL");
    opts.optopt("", "proc", "Mount procfs on DEST", "DEST");
    opts.optopt("", "dev", "Mount new dev on DEST", "DEST");
    opts.optopt("", "tmpfs", "Mount new tmpfs on DEST", "DEST");
    opts.optopt("", "mqueue", "Mount new mqueue on DEST", "DEST");
    opts.optopt("", "dir", "Create dir at DEST", "DEST");
    opts.optopt("", "file", "DEST               Copy from FD to dest DEST", "FD");
    opts.optopt("", "bind-data", "DEST          Copy from FD to file which is bind-mounted on DEST", "FD");
    opts.optopt("", "ro-bind-data", "DEST       Copy from FD to file which is readonly bind-mounted on DEST", "FD");
    opts.optopt("", "symlink", "DEST           Create symlink at DEST with target SRC", "SRC");
    opts.optopt("", "seccomp", "Load and use seccomp rules from FD", "FD");
    opts.optopt("", "block-fd", "Block on FD until some data to read is available", "FD");
    opts.optopt("", "info-fd", "Write information about the running container to FD", "FD");
    opts.optflag("", "new-session", "Create a new terminal session");
    opts.optflag("", "die-with-parent", "Kills with SIGKILL child process (COMMAND) when bwrap or bwrap's parent dies.");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => { panic!(f.to_string()) },
    };

    if matches.opt_present("h") {
        usage(&program, opts);
        return
    }

    println!("Hello, world!");
}
