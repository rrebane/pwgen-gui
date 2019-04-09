import re

class SolverError(Exception):
    pass

class Solver:
    def __init__(self, _vendor, _description, _example, _validator_str, _solve_func):
        self.vendor = _vendor
        self.description = _description
        self.example = _example
        self.validator = re.compile(_validator_str)
        self.solve_func = _solve_func

    def is_valid_input(self, in_str):
        return bool(self.validator.match(in_str))

    def solve(self, in_str):
        if not self.is_valid_input(in_str):
            raise SolverError('Invalid input string: ' + in_str)

        return self.solve_func(in_str)
