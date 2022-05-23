# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

#TODO: How do we interact w/ canaries???? Or maybe don't even have to?

import angr
import sys

def main(argv):
    proj = angr.Project(argv[1])

    #Left off FILL UNCONSTRAINED options. Never 100% clear on whether those were needed.
    # Still works
    initial_state = proj.factory.entry_state()
    #TODO: What is veritest doing for us? W/ it takes 15seconds. W/o the fans just spin and no progress is made. 
    sim = proj.factory.simgr(initial_state, veritesting=True)

    sim.explore(find=0x08048693, avoid=0x0804869)

    if sim.found:
        sol_state = sim.found[0]
        print(sol_state.posix.dumps(0).decode())
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)