# This time, the solution involves simply replacing scanf with our own version,
# since Angr does not support requesting multiple parameters with scanf.

import angr
import claripy
import sys

def main(argv):
  # path_to_binary = argv[1]
  path_to_binary = '/Users/michaelboensel/Desktop/Dev/binary_exploitation_resources/angr_ctf/solutions/11_angr_sim_scanf/11_angr_sim_scanf'

  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  class ReplacementScanf(angr.SimProcedure):
    # Finish the parameters to the scanf function. Hint: 'scanf("%u %u", ...)'.
    # (!)
    def run(self, format_string, scanf0_address, scanf1_address):
      # Hint: scanf0_address is passed as a parameter, isn't it?
      scanf0 = claripy.BVS('scanf0', 32)
      scanf1 = claripy.BVS('scanf1', 32)

      # The scanf function writes user input to the buffers to which the 
      # parameters point.
      #TODO: Does it really need the endness specified? I don't think so. 
      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)


      # Now, we want to 'set aside' references to our symbolic values in the
      # globals plugin included by default with a state. You will need to
      # store multiple bitvectors. You can either use a list, tuple, or multiple
      # keys to reference the different bitvectors.
      # (!)
      # TODO: I have no idea why this is necessary (or even if it is...) 
      # Nor how it is used...
      # OK. It seems to be there so that the solution_state can grab it, despite it being in a function (and going out of scope)?
      self.state.globals['solution0'] = scanf0
      self.state.globals['solution1'] = scanf1

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good' in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Grab whatever you set aside in the globals dict.
    stored_solutions0 = solution_state.globals['solution0']
    stored_solutions1 = solution_state.globals['solution1']

    # TODO: Figuring out when to decode, when not to, not intuitive to me yet. 
    str0 = solution_state.solver.eval(stored_solutions0)

    str1 = solution_state.solver.eval(stored_solutions1)


    print("%u %u" % (str0 ,str1 ))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
