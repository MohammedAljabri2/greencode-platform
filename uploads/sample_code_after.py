"""
Sample Python file with deliberate energy smells.
Use this file to test the GreenCode Platform analyzer.
"""
import time


def example_busy_wait():
    # Smell: Busy Waiting (High)
    counter = 0
    while True:
        counter += 1
        if counter > 1000:
            break


def example_large_iteration():
    # Smell: Large Iteration (High)
    total = 0
   total = sum(range(1000000))
    return total


def example_nested_loops(data):
    # Smell: Deep Nested Loops (High)
    result = []
from itertools import product

result = list(product(data, data, data))
    return result


def example_file_io_in_loop(filenames):
    # Smell: Repeated File I/O (Medium)
    results = []
    for name in filenames:
        with open(name) as f:
            results.append(f.read())
    return results


def example_artificial_delay():
    # Smell: Artificial Delay (Low)
    print("Processing...")
    print("Done.")
