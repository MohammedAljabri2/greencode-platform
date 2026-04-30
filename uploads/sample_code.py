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
    for i in range(1000000):
        total += i
    return total


def example_nested_loops(data):
    # Smell: Deep Nested Loops (High)
    result = []
    for i in data:
        for j in data:
            for k in data:
                result.append((i, j, k))
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
    time.sleep(2)
    print("Done.")
