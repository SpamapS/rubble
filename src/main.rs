extern crate getopts;
extern crate nix;
use getopts::Options;
use std::env;
use nix::errno;
use nix::libc::{setfsuid, uid_t, prctl, PR_CAPBSET_DROP};
use nix::unistd::{geteuid, getuid};


fn usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    println!("{}", opts.usage(&brief));
}

/* This acquires the privileges that the rubble will need it to work.
 * If rubble is not setuid, then this does nothing, and it relies on
 * unprivileged user namespaces to be used. This case is
 * "is_privileged = FALSE".
 *
 * If rubble is setuid, then we do things in phases.
 * The first part is run as euid 0, but with with fsuid as the real user.
 * The second part, inside the child, is run as the real user but with
 * capabilities.
 * And finally we drop all capabilities.
 * The reason for the above dance is to avoid having the setup phase
 * being able to read files the user can't, while at the same time
 * working around various kernel issues. See below for details.
 */
fn acquire_privs(real_uid: uid_t, real_gid: uid_t) {

    let mut is_privileged: bool;

    let euid = geteuid();

    /* Are we setuid ? */
    if real_uid != euid {
        if euid == 0 {
            is_privileged = true;
        } else {
            panic!("Unexpected setuid user {} should be 0", euid);
        }

        /* We want to keep running as euid=0 until at the clone()
         * operation because doing so will make the user namespace be
         * owned by root, which makes it not ptrace:able by the user as
         * it otherwise would be. After that we will run fully as the
         * user, which is necessary e.g. to be able to read from a fuse
         * mount from the user.
         *
         * However, we don't want to accidentally mis-use euid=0 for
         * escalated filesystem access before the clone(), so we set
         * fsuid to the uid.
         */
        unsafe {
            if setfsuid(real_uid) < 0 {
                panic!("Unable to set fsuid");
            }
            /* XXX The man page for setfsuid says use -1, but unary
             * - as an operator isn't allowed on u32 */
            let new_fsuid = setfsuid(0 - 1 as u32);
            if new_fsuid != real_uid as i32 {
                panic!("Unable to set fsuid (was {})", new_fsuid);
            }
        }
        drop_cap_bounding_set();
    }
}

fn drop_cap_bounding_set() {
    /* We ignore both EINVAL and EPERM, as we are actually relying
     * on PR_SET_NO_NEW_PRIVS to ensure the right capabilities are
     * available.  EPERM in particular can happen with old, buggy
     * kernels.  See:
     *  https://github.com/projectatomic/bubblewrap/pull/175#issuecomment-278051373
     *  https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/security/commoncap.c?
     *  id=160da84dbb39443fdade7151bc63a88f8e953077
     */
    for cap in 0..63 {
        let res = unsafe { prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
        let err = errno::Errno::last();
        if res == -1 && !(err == errno::EINVAL || err == errno::EPERM) {
            panic!("Dropping capability {} from bounds", cap);
        }
    }
}


fn set_required_caps() {}



fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help");
    opts.optflag("V", "version", "Print version");
    opts.optopt("", "args", "Parse nul-separated args from FD", "FD");
    opts.optflag("",
                 "unshare-all",
                 "Unshare every namespace we support by default");
    opts.optflag("",
                 "share-net",
                 "Retain the network namespace (can only combine with --unshare-all)");
    opts.optflag("",
                 "unshare-user",
                 "Create new user namespace (may be automatically implied if not setuid)");
    opts.optflag("",
                 "unshare-user-try",
                 "Create new user namespace if possible else continue by skipping it");
    opts.optflag("", "unshare-ipc", "Create new ipc namespace");
    opts.optflag("", "unshare-pid", "Create new pid namespace");
    opts.optflag("", "unshare-net", "Create new network namespace");
    opts.optflag("", "unshare-uts", "Create new uts namespace");
    opts.optflag("", "unshare-cgroup", "Create new cgroup namespace");
    opts.optflag("",
                 "unshare-cgroup-try",
                 "Create new cgroup namespace if possible else continue by skipping it");
    opts.optopt("",
                "uid",
                "Custom uid in the sandbox (requires --unshare-user)",
                "UID");
    opts.optopt("",
                "gid",
                "Custon gid in the sandbox (requires --unshare-user)",
                "GID");
    opts.optopt("",
                "hostname",
                "Custom hostname in the sandbox (requires --unshare-uts)",
                "NAME");
    opts.optopt("", "chdir", "Change directory to DIR", "DIR");
    opts.optopt("",
                "setenv",
                "VALUE           Set an environment variable",
                "VAR");
    opts.optopt("", "unsetenv", "Unset an environment variable", "VAR");
    opts.optopt("",
                "lock-file",
                "Take a lock on DEST while sandbox is running",
                "DEST");
    opts.optopt("",
                "sync-fd",
                "Keep this fd open while sandbox is running",
                "FD");
    opts.optopt("",
                "bind",
                "DEST              Bind mount the host path SRC on DEST",
                "SRC");
    opts.optopt("",
                "dev-bind",
                "DEST          Bind mount the host path SRC on DEST, allowing device access",
                "SRC");
    opts.optopt("",
                "ro-bind",
                "DEST           Bind mount the host path SRC readonly on DEST",
                "SRC");
    opts.optopt("",
                "remount-ro",
                "Remount DEST as readonly, it doesn't recursively remount",
                "DEST");
    opts.optopt("", "exec-label", "Exec Label for the sandbox", "LABEL");
    opts.optopt("",
                "file-label",
                "File label for temporary sandbox content",
                "LABEL");
    opts.optopt("", "proc", "Mount procfs on DEST", "DEST");
    opts.optopt("", "dev", "Mount new dev on DEST", "DEST");
    opts.optopt("", "tmpfs", "Mount new tmpfs on DEST", "DEST");
    opts.optopt("", "mqueue", "Mount new mqueue on DEST", "DEST");
    opts.optopt("", "dir", "Create dir at DEST", "DEST");
    opts.optopt("",
                "file",
                "DEST               Copy from FD to dest DEST",
                "FD");
    opts.optopt("",
                "bind-data",
                "DEST          Copy from FD to file which is bind-mounted on DEST",
                "FD");
    opts.optopt("",
                "ro-bind-data",
                "DEST       Copy from FD to file which is readonly bind-mounted on DEST",
                "FD");
    opts.optopt("",
                "symlink",
                "DEST           Create symlink at DEST with target SRC",
                "SRC");
    opts.optopt("", "seccomp", "Load and use seccomp rules from FD", "FD");
    opts.optopt("",
                "block-fd",
                "Block on FD until some data to read is available",
                "FD");
    opts.optopt("",
                "info-fd",
                "Write information about the running container to FD",
                "FD");
    opts.optflag("", "new-session", "Create a new terminal session");
    opts.optflag("",
                 "die-with-parent",
                 "Kills with SIGKILL child process (COMMAND) when bwrap or bwrap's parent dies.");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    if matches.opt_present("h") {
        usage(&program, opts);
        return;
    }


    let real_uid = getuid();
    let real_gid = getuid();

    acquire_privs(real_uid, real_gid);

    println!("Hello, world!");
}
