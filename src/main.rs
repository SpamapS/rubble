extern crate caps;
extern crate env_logger;
extern crate getopts;
extern crate isatty;
#[macro_use]
extern crate log;
extern crate nix;
extern crate walkdir;
use caps::{Capability, CapSet};
use getopts::{Options, Matches};
use std::env;
use std::fs;
use std::fs::{DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::io::{ErrorKind, Read};
use std::path;
use std::str::FromStr;

use isatty::stdout_isatty;
use nix::errno;
use nix::libc::{eventfd, EFD_CLOEXEC, EFD_NONBLOCK, setfsuid, uid_t, gid_t, prctl, PR_CAPBSET_DROP,
                PR_SET_NO_NEW_PRIVS, SIGCHLD, CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWPID,
                CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP, ttyname};
use nix::sys::signal::{pthread_sigmask, SigmaskHow, Signal, SigSet};
use nix::unistd::{geteuid, getuid};
use nix::sys::wait::{waitpid, WNOHANG};
use walkdir::WalkDir;


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
fn acquire_privs(real_uid: uid_t, real_gid: uid_t) -> bool {

    let mut is_privileged: bool = false;

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
            /* setfsuid can't properly report errors, check that it worked (as per manpage) */
            /* XXX The man page for setfsuid says use -1, but unary
             * - as an operator isn't allowed on u32 */
            let new_fsuid = setfsuid(0 - 1 as u32);
            if new_fsuid != real_uid as i32 {
                panic!("Unable to set fsuid (was {})", new_fsuid);
            }
        }
        /* We never need capabilies after execve(), so lets drop everything from the bounding set */
        drop_cap_bounding_set();

        /* Keep only the required capabilities for setup */
        set_required_caps();
    } else if real_uid != 0 && has_caps() {
        /* We have some capabilities in the non-setuid case, which should not happen.
         Probably caused by the binary being setcap instead of setuid which we
         don't support anymore */
        panic!("Unexpected capabilities but not setuid, old file caps config?");
    }
    /* Else, we try unprivileged user namespaces */
    is_privileged
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

fn _set_required_caps() -> caps::Result<()> {
    for cap in vec![Capability::CAP_SYS_ADMIN,
                    Capability::CAP_SYS_CHROOT,
                    Capability::CAP_NET_ADMIN,
                    Capability::CAP_SETUID,
                    Capability::CAP_SETGID] {
        caps::raise(None, CapSet::Effective, cap)?;
        caps::raise(None, CapSet::Permitted, cap)?;
        caps::clear(None, CapSet::Inheritable)?;
    }
    Ok(())
}

fn set_required_caps() {
    match _set_required_caps() {
        Ok(_) => {}
        Err(e) => {
            panic!("Failure manipulating capabilities. {}", e);
        }
    };
}

fn has_caps() -> bool {
    match caps::read(None, CapSet::Permitted) {
        Ok(caps) => !caps.is_empty(),
        Err(e) => {
            panic!("capget failed {}", e);
        }
    }
}

fn read_overflowids() -> (uid_t, gid_t) {
    let mut uid_data = String::new();
    File::open("/proc/sys/kernel/overflowuid").unwrap().read_to_string(&mut uid_data).unwrap();
    let overflow_uid: uid_t = match uid_data.trim().parse() {
        Ok(parsed) => parsed,
        Err(e) => panic!("Could not parse {} as uid_t: {}", uid_data, e),
    };

    let mut gid_data = String::new();
    File::open("/proc/sys/kernel/overflowgid").unwrap().read_to_string(&mut gid_data).unwrap();
    let overflow_gid: gid_t = match gid_data.trim().parse() {
        Ok(parsed) => parsed,
        Err(e) => panic!("Could not parse {} as gid_t: {}", gid_data, e),
    };

    (overflow_uid, overflow_gid)
}

fn block_sigchild() {
    let mut childset = SigSet::empty();
    childset.add(Signal::SIGCHLD);
    match pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&childset), None) {
        Err(e) => panic!("sigprocmask: {}", e),
        _ => {}
    }

    /* Reap any outstanding zombies that we may have inherited */
    loop {
        match waitpid(-1, Some(WNOHANG)) {
            Err(_) => break,
            _ => {}
        }
    }
}

fn setup_opts(opts: &mut Options) {
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
}

struct ParsedOpts {
    sandbox_uid: Option<uid_t>,
    sandbox_gid: Option<gid_t>,
}

fn parse_one_opt<T: FromStr>(matches: &Matches, nm: &str) -> Option<T>
    where <T as std::str::FromStr>::Err: std::fmt::Display
{
    match matches.opt_str(nm) {
        None => None,
        Some(opt_str) => {
            match opt_str.parse::<T>() {
                Err(e) => panic!("Could not parse {}: {}", opt_str, e),
                Ok(opt_parsed) => Some(opt_parsed),
            }
        }
    }
}


fn parse_opts(matches: &Matches) -> ParsedOpts {
    ParsedOpts {
        sandbox_uid: parse_one_opt(matches, "uid"),
        sandbox_gid: parse_one_opt(matches, "gid"),
    }
}

fn main() {
    let real_uid = getuid();
    let real_gid = getuid();

    /* Get the (optional) privileges we need */
    let is_privileged = acquire_privs(real_uid, real_gid);

    /* Never gain any more privs during exec */
    unsafe {
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            panic!("prctl(PR_SET_NO_NEW_CAPS) failed");
        }
    }

    /* The initial code is run with high permissions
       (i.e. CAP_SYS_ADMIN), so take lots of care. */

    let (overflow_uid, overflow_gid) = read_overflowids();

    let mut host_tty_dev: Option<String> = None;
    if stdout_isatty() {
        host_tty_dev = Some(unsafe {
            let tty_ptr = ttyname(1);
            let mut tty_string: Vec<u8> = Vec::new();
            let mut i = 0;
            while *tty_ptr.offset(i) != 0 {
                tty_string.push(*tty_ptr.offset(i) as u8);
                i += 1;
            }
            let tty_string = String::from_utf8(tty_string).unwrap();
            tty_string
        });
    }

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    setup_opts(&mut opts);

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let popts = parse_opts(&matches);

    if matches.opt_present("h") {
        usage(&program, opts);
        return;
    }

    env_logger::init().unwrap();

    let mut opt_unshare_user = matches.opt_present("unshare-user");
    /* We have to do this if we weren't installed setuid (and we're not
     * root), so let's just DWIM */
    if !is_privileged && getuid() != 0 {
        opt_unshare_user = true;
    }

    // #ifdef ENABLE_REQUIRE_USERNS
    /* In this build option, we require userns. */
    if is_privileged && getuid() != 0 {
        opt_unshare_user = true;
    }
    // #endif

    if matches.opt_present("unshare-user-try") && fs::metadata("/proc/self/ns/user").is_ok() {
        let mut disabled = false;

        /* RHEL7 has a kernel module parameter that lets you enable user namespaces */
        if fs::metadata("/sys/module/user_namespace/parameters/enable").is_ok() {
            match File::open("/sys/module/user_namespace/parameters/enable") {
                Err(_) => {}
                Ok(mut f) => {
                    let mut enable = String::new();
                    f.read_to_string(&mut enable).unwrap();
                    match enable.chars().next() {
                        Some(c) if c == 'N' => disabled = true,
                        _ => {}
                    }
                }
            }
        }

        /* Debian lets you disable *unprivileged* user namespaces. However this is not
           a problem if we're privileged, and if we're not opt_unshare_user is TRUE
           already, and there is not much we can do, its just a non-working setup. */

        if !disabled {
            opt_unshare_user = true;
        }
    }
    let opt_unshare_user = opt_unshare_user; // No more changes!

    debug!("Creating root mount point");

    let opt_sandbox_uid = match popts.sandbox_uid {
        None => real_uid,
        Some(uid) => uid,
    };
    let opt_sandbox_gid = match popts.sandbox_gid {
        None => real_gid,
        Some(gid) => gid,
    };

    if !matches.opt_present("unshare-user") && popts.sandbox_uid.is_some() {
        panic!("Specifying --uid requires --unshare-user");
    }

    if !matches.opt_present("unshare-user") && popts.sandbox_gid.is_some() {
        panic!("Specifying --gid requires --unshare-user");
    }

    if !matches.opt_present("unshare-uts") && matches.opt_present("hostname") {
        panic!("Specifying --hostname requires --unshare-uts");
    }

    /* We need to read stuff from proc during the pivot_root dance, etc.
       Lets keep a fd to it open */
    if !path::Path::new("/proc").exists() {
        panic!("Can't open /proc");
    }
    let proc_wd = WalkDir::new("/proc");

    /* We need *some* mountpoint where we can mount the root tmpfs.
     We first try in /run, and if that fails, try in /tmp. */
    let base_path = format!("/run/user/{}/.bubblewrap", real_uid);
    match DirBuilder::new().mode(0o755).create(base_path) {
        Err(ref e) if e.kind() != ErrorKind::AlreadyExists => {
            let base_path = format!("/tmp/.bubblewrap-{}", real_uid);
            match DirBuilder::new().mode(0o755).create(base_path) {
                Err(ref e) if e.kind() != ErrorKind::AlreadyExists => {
                    panic!("Creating root mountpoint failed");
                }
                _ => {}
            };
        }
        _ => {}
    }

    debug!("creating new namespace");

    let mut event_fd: Option<i32> = None;
    if matches.opt_present("unshare-pid") {
        unsafe {
            event_fd = match eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) {
                -1 => panic!("eventfd()"),
                event_fd => Some(event_fd),
            };
        }
    }


    /* We block sigchild here so that we can use signalfd in the monitor. */
    block_sigchild();

    let mut clone_flags = SIGCHLD | CLONE_NEWNS;
    if matches.opt_present("unshare-user") {
        clone_flags |= CLONE_NEWUSER;
    }
    if matches.opt_present("unshare-pid") {
        clone_flags |= CLONE_NEWPID;
    }
    if matches.opt_present("unshare-net") {
        clone_flags |= CLONE_NEWNET;
    }
    if matches.opt_present("unshare-ipc") {
        clone_flags |= CLONE_NEWUTS;
    }
    if matches.opt_present("unshare-cgroup") {
        match fs::metadata("/proc/self/ns/cgroup") {
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                panic!("Cannot create new cgroup namespace because the kernel does not support it")
            }
            Err(e) => panic!("stat on /proc/self/ns/cgroup failed"),
            _ => {}
        }
        clone_flags |= CLONE_NEWCGROUP;
    }

    println!("Hello, world!");
}
