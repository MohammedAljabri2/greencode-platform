"""
GreenCode Platform - Static Analysis Engine
===========================================
Improved rule-based analyzer that supports both Python and Java and
mitigates false positives by skipping comments and tracking loop context.

Traceability:
- FR-02 Static Analysis       -> analyze_file()
- FR-03 Detect Energy Smells  -> _scan_lines()
- FR-04 Classify Severity     -> severity field on each rule
- FR-05 Recommendations       -> suggestion field on each rule
- FR-06 / FR-07 Scoring       -> _compute_score()
"""
import re

# ---------------------------------------------------------------------------
# Severity-weighted penalty table (used by the scoring function)
# ---------------------------------------------------------------------------
SEVERITY_PENALTY = {"High": 15, "Medium": 8, "Low": 3}

# ---------------------------------------------------------------------------
# Python energy-smell rules
# Each rule: dict with keys type, severity, patterns, suggestion
# Patterns are compiled regexes applied to each non-comment line
# ---------------------------------------------------------------------------
PYTHON_RULES = [
    {
        "type": "Busy Waiting",
        "severity": "High",
        "patterns": [re.compile(r"\bwhile\s+True\b")],
        "skip_if_break_nearby": True,
        "reason": "Infinite loop may waste CPU continuously.",
        "suggestion": ("Avoid infinite loops",
                       "Use an event-driven mechanism or add a proper stopping condition."),
    },
    {
        "type": "Large Iteration",
        "severity": "High",
        "patterns": [
            re.compile(r"range\s*\(\s*1\s*0{5,}\s*\)"),  # range(100000+)
        ],
        "reason": "Very large loops consume significant CPU time and energy.",
        "suggestion": ("Reduce loop size",
                       "Use vectorization (NumPy), generators, or a more efficient algorithm."),
    },
    {
        "type": "Artificial Delay",
        "severity": "Low",
        "patterns": [re.compile(r"time\.sleep\s*\(")],
        "reason": "Artificial delays keep the process idle but still consuming resources.",
        "suggestion": ("Remove unnecessary delays",
                       "Use proper async primitives, event loops, or timers instead of sleep."),
    },
    {
        "type": "String Concatenation in Loop",
        "severity": "Medium",
        "patterns": [re.compile(r"\w+\s*\+=\s*['\"].*['\"]")],
        "requires_loop_context": True,
        "reason": "Building a string with += inside a loop allocates many temporary objects.",
        "suggestion": ("Use list + join",
                       "Collect pieces in a list and call ''.join(parts) once after the loop."),
    },
    {
        "type": "Repeated len() in Loop Condition",
        "severity": "Medium",
        "patterns": [re.compile(r"while\s+\w+\s*<\s*len\s*\(")],
        "reason": "Calling len() every iteration repeats the same computation.",
        "suggestion": ("Cache the length",
                       "Compute n = len(items) once before the loop."),
    },
    {
        "type": "Inefficient Membership Test on List Literal",
        "severity": "Medium",
        "patterns": [re.compile(r"\s+in\s+\[[^\]]{20,}\]")],
        "reason": "Searching a large list literal is O(n); a set is O(1).",
        "suggestion": ("Use a set for lookups",
                       "Replace the list literal with a set: x in {'a', 'b', 'c'}."),
    },
    {
        "type": "Print in Loop",
        "severity": "Low",
        "patterns": [re.compile(r"\bprint\s*\(")],
        "requires_loop_context": True,
        "reason": "Frequent I/O inside loops writes to the terminal unnecessarily.",
        "suggestion": ("Batch or log output",
                       "Accumulate output and print once, or use a logger with level filtering."),
    },
]

# ---------------------------------------------------------------------------
# Java energy-smell rules
# ---------------------------------------------------------------------------
JAVA_RULES = [
    {
        "type": "Busy Waiting",
        "severity": "High",
        "patterns": [re.compile(r"\bwhile\s*\(\s*true\s*\)")],
        "reason": "Infinite loop without proper wait mechanism wastes CPU.",
        "suggestion": ("Use wait/notify",
                       "Use Object.wait() or java.util.concurrent primitives."),
    },
    {
        "type": "String Concatenation in Loop",
        "severity": "High",
        # Fires only inside a loop on `X += ...` lines where X is not obviously numeric.
        # This gives good recall for strings while minimising noise on counters.
        "patterns": [
            re.compile(r"\w+\s*\+=\s*\""),              # result += "literal"
            re.compile(r"\w+\s*\+=\s*\w+\s*[\[\.]"),    # result += names[i] or result += obj.x
        ],
        "requires_loop_context": True,
        "reason": "String += in a Java loop creates many intermediate String objects, "
                  "pressuring the garbage collector.",
        "suggestion": ("Use StringBuilder",
                       "Append to a StringBuilder inside the loop and call toString() once."),
    },
    {
        "type": "System.out.println in Loop",
        "severity": "Low",
        "patterns": [re.compile(r"System\.out\.(println|print)\s*\(")],
        "requires_loop_context": True,
        "reason": "Frequent console I/O in tight loops is an expensive energy drain.",
        "suggestion": ("Use a logging framework",
                       "Accumulate output or use SLF4J/Logback with level filtering."),
    },
    {
        "type": "Object Allocation in Loop",
        "severity": "Medium",
        "patterns": [re.compile(r"\bnew\s+[A-Z]\w+\s*\(")],
        "requires_loop_context": True,
        "reason": "Allocating new objects every iteration stresses the garbage collector.",
        "suggestion": ("Reuse objects",
                       "Move the allocation outside the loop or use an object pool."),
    },
    {
        "type": "Thread.sleep()",
        "severity": "Low",
        "patterns": [re.compile(r"Thread\.sleep\s*\(")],
        "reason": "Blocking the thread wastes resources without doing useful work.",
        "suggestion": ("Use ScheduledExecutorService",
                       "Replace Thread.sleep with a properly scheduled task."),
    },
]


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------
def _strip_comment(line, language):
    """Remove trailing comments so rules don't match commented-out code."""
    if language == "python":
        idx = line.find("#")
        if idx >= 0:
            # Avoid stripping a # inside a string (simple heuristic)
            before = line[:idx]
            if before.count('"') % 2 == 0 and before.count("'") % 2 == 0:
                return line[:idx]
        return line
    if language == "java":
        idx = line.find("//")
        if idx >= 0:
            return line[:idx]
        return line
    return line


def _is_blank_or_comment(stripped_line, language):
    if not stripped_line:
        return True
    if language == "python" and stripped_line.startswith("#"):
        return True
    if language == "java" and (stripped_line.startswith("//") or
                               stripped_line.startswith("*") or
                               stripped_line.startswith("/*")):
        return True
    return False


def _indent(line):
    return len(line) - len(line.lstrip())


def _has_break_in_block(lines, start_idx, block_indent, language):
    """Return True if a break/return/raise exists inside the while True block."""
    i = start_idx + 1
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if _indent(line) <= block_indent and stripped:
            break
        if language == "python":
            if re.search(r"\b(break|return|raise|sys\.exit)\b", stripped):
                return True
        else:
            if re.search(r"\b(break|return|throw)\b", stripped):
                return True
        i += 1
    return False


def _inside_loop(lines, idx, language):
    """Check whether line idx is inside a for/while block by looking upward."""
    target_indent = _indent(lines[idx])
    if target_indent == 0:
        return False
    i = idx - 1
    while i >= 0:
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i -= 1
            continue
        cur_indent = _indent(line)
        if cur_indent < target_indent:
            # Check if this enclosing line starts a loop
            if language == "python":
                if stripped.startswith("for ") or stripped.startswith("while "):
                    return True
            else:  # java
                if re.match(r"(for|while)\s*\(", stripped):
                    return True
            target_indent = cur_indent
        i -= 1
    return False


def _detect_nested_depth(lines, idx, language):
    """Count the maximum loop-nesting depth at line idx.
    Uses indentation for Python, brace/keyword counting for Java (approx)."""
    line = lines[idx]
    stripped = line.strip()
    if language == "python":
        if not (stripped.startswith("for ") or stripped.startswith("while ")):
            return 0
        base_indent = _indent(line)
        depth = 1
        j = idx + 1
        while j < len(lines):
            nxt = lines[j]
            nxt_stripped = nxt.strip()
            if not nxt_stripped:
                j += 1
                continue
            if _indent(nxt) <= base_indent:
                break
            if nxt_stripped.startswith("for ") or nxt_stripped.startswith("while "):
                inner_depth = _detect_nested_depth(lines, j, "python")
                depth = max(depth, 1 + inner_depth)
            j += 1
        return depth
    else:  # java - approximate nesting from indent
        if not re.match(r"(for|while)\s*\(", stripped):
            return 0
        base_indent = _indent(line)
        depth = 1
        j = idx + 1
        while j < len(lines):
            nxt = lines[j]
            nxt_stripped = nxt.strip()
            if not nxt_stripped:
                j += 1
                continue
            if _indent(nxt) <= base_indent:
                break
            if re.match(r"(for|while)\s*\(", nxt_stripped):
                depth = max(depth, 2)
            j += 1
        return depth


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------
def analyze_file(content, file_path, language="python"):
    """
    Analyze a single file's content and return:
        (score, list_of_smells, list_of_suggestions, lines_of_code)

    - score is an int 0..100 (100 = fully sustainable)
    - smells are tuples (smell_type, severity, line_no, reason)
    - suggestions are tuples (title, description)
    """
    lines = content.splitlines()
    rules = PYTHON_RULES if language == "python" else JAVA_RULES

    smells = []
    suggestions = []

    # Track previously-detected smells to avoid duplicates per file+line+type
    seen_smells = set()

    for i, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if _is_blank_or_comment(stripped, language):
            continue
        line = _strip_comment(raw_line, language)
        line_stripped = line.strip()

        # Apply each rule
        for rule in rules:
            # Context requirements
            if rule.get("requires_loop_context") and not _inside_loop(lines, i, language):
                continue

            for pattern in rule["patterns"]:
                if pattern.search(line):
                    # Special: busy-wait check - skip if there's a break in the block
                    if rule.get("skip_if_break_nearby"):
                        if _has_break_in_block(lines, i, _indent(raw_line), language):
                            continue

                    key = (rule["type"], i + 1)
                    if key in seen_smells:
                        continue
                    seen_smells.add(key)

                    smells.append((rule["type"], rule["severity"],
                                   i + 1, rule["reason"]))
                    suggestions.append(rule["suggestion"])
                    break  # one hit per rule per line is enough

        # Deep-nested-loop detection
        if (language == "python" and (line_stripped.startswith("for ") or
                                      line_stripped.startswith("while "))) or \
           (language == "java" and re.match(r"(for|while)\s*\(", line_stripped)):
            depth = _detect_nested_depth(lines, i, language)
            if depth >= 3:
                key = ("Deep Nested Loops", i + 1)
                if key not in seen_smells:
                    seen_smells.add(key)
                    smells.append(("Deep Nested Loops", "High", i + 1,
                                   f"Loops nested {depth} deep lead to very high computational cost."))
                    suggestions.append(("Reduce nested loops",
                                        "Flatten the logic, use set/dict lookups, "
                                        "or extract inner loops into separate functions."))
            elif depth == 2:
                key = ("Nested Loops", i + 1)
                if key not in seen_smells:
                    seen_smells.add(key)
                    smells.append(("Nested Loops", "Medium", i + 1,
                                   "Nested loops increase complexity quadratically."))
                    suggestions.append(("Optimize loop structure",
                                        "Consider vectorization or set/dict membership checks."))

    # Deduplicate suggestions
    unique_suggestions = []
    seen_sug = set()
    for title, desc in suggestions:
        if (title, desc) not in seen_sug:
            seen_sug.add((title, desc))
            unique_suggestions.append((title, desc))

    score = _compute_score(smells, len(lines))
    return score, smells, unique_suggestions, len(lines)


def _compute_score(smells, loc):
    """
    Compute a 0..100 Sustainability Score.
    The penalty is severity-weighted and normalised per 100 lines of code.
    """
    if loc == 0:
        return 100.0
    penalty = sum(SEVERITY_PENALTY.get(s[1], 5) for s in smells)
    normalised = min(penalty * 100 / max(loc, 1), 95.0)
    return round(max(5.0, 100.0 - normalised), 1)
