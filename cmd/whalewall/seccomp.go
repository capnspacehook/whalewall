package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

var allowedSyscalls = seccomp.SyscallRules{
	unix.SYS_ACCESS: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_OK),
		},
	},
	unix.SYS_BIND: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(12),
		},
	},
	unix.SYS_CLOCK_GETTIME: {
		{
			seccomp.EqualTo(unix.CLOCK_MONOTONIC),
			seccomp.MatchAny{},
		},
		{
			seccomp.EqualTo(unix.CLOCK_REALTIME),
			seccomp.MatchAny{},
		},
	},
	unix.SYS_CLONE: {
		// parent_tidptr and child_tidptr are always 0 because neither
		// CLONE_PARENT_SETTID nor CLONE_CHILD_SETTID are used.
		{
			seccomp.EqualTo(
				unix.CLONE_VM |
					unix.CLONE_FS |
					unix.CLONE_FILES |
					unix.CLONE_SETTLS |
					unix.CLONE_SIGHAND |
					unix.CLONE_SYSVSEM |
					unix.CLONE_THREAD),
			seccomp.MatchAny{}, // newsp
			seccomp.EqualTo(0), // parent_tidptr
			seccomp.EqualTo(0), // child_tidptr
			seccomp.MatchAny{}, // tls
		},
	},
	unix.SYS_CLOSE:   {},
	unix.SYS_CONNECT: {},
	unix.SYS_EPOLL_CREATE1: {
		{
			seccomp.EqualTo(unix.EPOLL_CLOEXEC),
		},
	},
	unix.SYS_EPOLL_CTL: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.EPOLL_CTL_ADD),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.EPOLL_CTL_DEL),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
	},
	unix.SYS_EPOLL_PWAIT: {},
	unix.SYS_EXIT_GROUP:  {},
	unix.SYS_FCHMOD: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(0o644),
		},
	},
	unix.SYS_FCHOWN: {},
	unix.SYS_FCNTL: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_GETFL),
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_SETFL),
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_GETLK),
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_SETLK),
			seccomp.MatchAny{},
		},
	},
	unix.SYS_FSTAT:     {},
	unix.SYS_FSYNC:     {},
	unix.SYS_FTRUNCATE: {},
	unix.SYS_FUTEX: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_GETCWD:      {},
	unix.SYS_GETEUID:     {},
	unix.SYS_GETPEERNAME: {},
	unix.SYS_GETPID:      {},
	unix.SYS_GETSOCKNAME: {},
	unix.SYS_GETSOCKOPT: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_ERROR),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
	},
	unix.SYS_GETTID:  {},
	unix.SYS_LSEEK:   {},
	unix.SYS_LSTAT:   {},
	unix.SYS_MADVISE: {},
	unix.SYS_MMAP: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_SHARED),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_MUNMAP:     {},
	unix.SYS_NANOSLEEP:  {},
	unix.SYS_NEWFSTATAT: {},
	unix.SYS_OPENAT:     {},
	unix.SYS_PIPE2:      {},
	unix.SYS_READ:       {},
	unix.SYS_RECVMSG: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MSG_PEEK),
		},
	},
	unix.SYS_RESTART_SYSCALL: {},
	unix.SYS_RT_SIGACTION:    {},
	unix.SYS_RT_SIGPROCMASK:  {},
	unix.SYS_RT_SIGRETURN:    {},
	unix.SYS_SCHED_YIELD:     {},
	unix.SYS_SENDMSG: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_SETSOCKOPT: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_BROADCAST),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_IPV6),
			seccomp.EqualTo(unix.IPV6_V6ONLY),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_NODELAY),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_KEEPALIVE),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_KEEPINTVL),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_KEEPIDLE),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
	},
	unix.SYS_SIGALTSTACK: {},
	unix.SYS_SOCKET: {
		// connecting to Docker API over TCP
		{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		// preforming DNS lookups for Docker API host
		{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_DGRAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_DGRAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		// connecting to Docker API over a unix socket
		{
			seccomp.EqualTo(unix.AF_UNIX),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		// connecting to netlink to manage nftables rules
		{
			seccomp.EqualTo(unix.AF_NETLINK),
			seccomp.EqualTo(unix.SOCK_RAW | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(unix.NETLINK_NETFILTER),
		},
	},
	unix.SYS_STAT: {},
	unix.SYS_TGKILL: {
		{
			seccomp.EqualTo(uint64(os.Getpid())),
		},
	},
	unix.SYS_TIME:  {},
	unix.SYS_WRITE: {},
}

type nullEmitter struct{}

func (nullEmitter) Emit(depth int, level log.Level, timestamp time.Time, format string, v ...interface{}) {
}

func installSeccompFilters() (int, error) {
	// disable logging from seccomp package
	log.SetTarget(&nullEmitter{})

	return len(allowedSyscalls), seccomp.Install(allowedSyscalls, seccomp.DenyNewExecMappings)
}
