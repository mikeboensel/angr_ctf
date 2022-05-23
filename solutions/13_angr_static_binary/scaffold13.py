# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.

import sys
import angr

def main(argv):
    proj = angr.Project(argv[1])
    # TODO: What is supposed to be used? blank_state or entry_state (w/ suitable address)?
    # proj.factory.blank_state(add

    # Different scenarios:
    # 1. entry_state (default entry point) + glibc_start replacement => WORKS (20 seconds)
    # 2. entry_state (default entry point) by itself => Fan spin (let run for 1min)
    # 3. main defined entry point + glibc_start replacement => WORKS (19 seconds)
    # 4. main defined entry point by itself => WORKS (19 sec)

    # TODO: LOL. They used entry_state in the solution... after explicitly saying not to before. 
    # init_state = proj.factory.entry_state()
    # Skipping into main(). Does this mean we don't have to worry about __libc_start_main anymore?
    init_state = proj.factory.entry_state(addr=0x080489e7)

    # Using SimProcedure hooking based on address (probably could have used Symbol name as well since non-stripped)
    proj.hook(0x0804fab0, angr.SIM_PROCEDURES['libc']['printf']())
    proj.hook(0x804fb10, angr.SIM_PROCEDURES['libc']['scanf']())
    proj.hook(0x80503f0, angr.SIM_PROCEDURES['libc']['puts']())
    #TODO: They explicitly said not to use entry_state, which I would think means we don't need this...
    # proj.hook(0x8048d60, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    sim = proj.factory.simgr(init_state)

    sim.explore(find=0x08048ac5, avoid=0x08048ab3)

    if sim.found:
        found_state = sim.found[0]
        print(found_state.posix.dumps(0))
    else:
        raise Exception("Nope")


if __name__ == '__main__':
  main(sys.argv)