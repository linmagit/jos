#ifndef JOS_KERN_MONITOR_H
#define JOS_KERN_MONITOR_H
#ifndef JOS_KERNEL
# error "This is a JOS kernel header; user programs should not #include it"
#endif

struct Trapframe;

// Activate the kernel monitor,
// optionally providing a trap frame indicating the current state
// (NULL if none).
void monitor(struct Trapframe *tf);

// Functions implementing monitor commands.
int mon_help(int argc, char **argv, struct Trapframe *tf);
int mon_kerninfo(int argc, char **argv, struct Trapframe *tf);
int mon_backtrace(int argc, char **argv, struct Trapframe *tf);
int mon_showmappings(int argc, char **argv, struct Trapframe *tf);
int setPerm(int argc, char **argv, struct Trapframe *tf);
int vpm(int argc, char **argv, struct Trapframe *tf);
int vvm(int argc, char **argv, struct Trapframe *tf);
int bcontinue(int argc, char **argv, struct Trapframe *tf);

#endif	// !JOS_KERN_MONITOR_H
