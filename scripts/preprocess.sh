#!/usr/bin/env bash

if [ $# -ne 1 ]; then
  echo "Usage: $0 input.c" >&2
  exit 2
fi

python3 - "$1" <<'PY' || exit 1
import sys
import re

fn = sys.argv[1]
s = open(fn, 'r', encoding='utf-8').read()

out = []
i = 0
N = len(s)

def peek(k=1):
    return s[i:i+k]

def is_ident_char(ch):
    return ch.isalnum() or ch == '_'

def skip_string_quote(q):
    # returns consumed string (including quotes)
    global i
    res = []
    res.append(s[i]); i += 1
    while i < N:
        ch = s[i]
        res.append(ch); i += 1
        if ch == '\\' and i < N:
            # escaped char: append next char too
            res.append(s[i]); i += 1
            continue
        if ch == q:
            break
    return ''.join(res)

def skip_line_comment():
    global i
    res = []
    while i < N:
        ch = s[i]; res.append(ch); i += 1
        if ch == '\n':
            break
    return ''.join(res)

def skip_block_comment():
    global i
    res = []
    res.append(s[i]); i += 1  # '/'
    res.append(s[i]); i += 1  # '*'
    while i < N:
        if s[i] == '*' and i+1 < N and s[i+1] == '/':
            res.append('*'); res.append('/'); i += 2
            break
        else:
            res.append(s[i]); i += 1
    return ''.join(res)

def consume_whitespace_and_comments_from(pos):
    # returns new pos skipping whitespace and comments (but not newlines necessarily)
    j = pos
    while j < N:
        if s[j].isspace():
            j += 1
            continue
        if s[j] == '/' and j+1 < N and s[j+1] == '/':
            # skip till newline inclusive
            k = s.find('\n', j+2)
            if k == -1:
                return N
            j = k+1
            continue
        if s[j] == '/' and j+1 < N and s[j+1] == '*':
            k = s.find('*/', j+2)
            if k == -1:
                return N
            j = k+2
            continue
        break
    return j

def find_matching_paren(pos):
    # pos is position of '('
    depth = 0
    j = pos
    while j < N:
        ch = s[j]
        if ch == '(':
            depth += 1
            j += 1
        elif ch == ')':
            depth -= 1
            j += 1
            if depth == 0:
                return j  # position after closing ')'
        elif ch == '"' or ch == "'":
            # skip string/char
            q = ch
            j += 1
            while j < N:
                if s[j] == '\\':
                    j += 2
                elif s[j] == q:
                    j += 1
                    break
                else:
                    j += 1
        elif ch == '/' and j+1 < N and s[j+1] == '/':
            # skip line comment
            k = s.find('\n', j+2)
            if k == -1:
                return N
            j = k+1
        elif ch == '/' and j+1 < N and s[j+1] == '*':
            k = s.find('*/', j+2)
            if k == -1:
                return N
            j = k+2
        else:
            j += 1
    return -1

def find_statement_end(pos):
    # Starting at pos (first non-space of a statement),
    # find the position after the statement ends (position right after the semicolon
    # that ends it OR right after a closing brace if it is a block).
    j = pos
    while j < N and s[j].isspace():
        j += 1
    if j >= N:
        return j
    if s[j] == '{':
        # need to find matching brace
        depth = 0
        while j < N:
            ch = s[j]
            if ch == '{':
                depth += 1; j += 1
            elif ch == '}':
                depth -= 1; j += 1
                if depth == 0:
                    return j
            elif ch == '"' or ch == "'":
                q = ch; j += 1
                while j < N:
                    if s[j] == '\\': j += 2
                    elif s[j] == q: j += 1; break
                    else: j += 1
            elif ch == '/' and j+1 < N and s[j+1] == '/':
                k = s.find('\n', j+2)
                if k == -1: return N
                j = k+1
            elif ch == '/' and j+1 < N and s[j+1] == '*':
                k = s.find('*/', j+2)
                if k == -1: return N
                j = k+2
            else:
                j += 1
        return j
    else:
        # parse until semicolon at depth 0 (ignore parentheses/braces inside)
        depth = 0
        while j < N:
            ch = s[j]
            if ch == ';' and depth == 0:
                return j+1
            elif ch == '(':
                depth += 1; j += 1
            elif ch == ')':
                depth = max(0, depth-1); j += 1
            elif ch == '{':
                # statement contains a block start - treat accordingly by finding its end
                end = find_statement_end(j)
                j = end
            elif ch == '"' or ch == "'":
                q = ch; j += 1
                while j < N:
                    if s[j] == '\\': j += 2
                    elif s[j] == q: j += 1; break
                    else: j += 1
            elif ch == '/' and j+1 < N and s[j+1] == '/':
                k = s.find('\n', j+2)
                if k == -1: return N
                j = k+1
            elif ch == '/' and j+1 < N and s[j+1] == '*':
                k = s.find('*/', j+2)
                if k == -1: return N
                j = k+2
            else:
                j += 1
        return j

# Main loop
i = 0
while i < N:
    ch = s[i]
    # copy strings and comments verbatim
    if ch == '"' or ch == "'":
        out.append(skip_string_quote(ch))
        continue
    if ch == '/' and i+1 < N and s[i+1] == '/':
        out.append(skip_line_comment()); continue
    if ch == '/' and i+1 < N and s[i+1] == '*':
        out.append(skip_block_comment()); continue

    # match identifiers (we'll check for control words)
    if ch.isalpha() or ch == '_':
        # read identifier
        j = i
        while j < N and (s[j].isalnum() or s[j] == '_'):
            j += 1
        ident = s[i:j]
        # lookahead for control keywords followed by optional space and '('
        if ident in ('if','for','while'):
            # ensure not part of a larger identifier (we already ensured word boundary)
            k = j
            # skip whitespace
            while k < N and s[k].isspace():
                k += 1
            if k < N and s[k] == '(':
                # find end of condition
                after_paren = find_matching_paren(k)
                if after_paren == -1:
                    # malformed; just copy ident and continue
                    out.append(s[i:j])
                    i = j
                    continue
                # determine where controlled statement begins (first nonspace after paren)
                stmt_start = consume_whitespace_and_comments_from(after_paren)
                if stmt_start >= N:
                    # nothing after condition; just copy
                    out.append(s[i:j])
                    i = j
                    continue
                # If the next non-space char is '{' -> insert INSTRUMENT; after the '{' (i.e. inside block)
                if s[stmt_start] == '{':
                    # copy everything up to and including '{'
                    out.append(s[i:stmt_start+1])
                    # after '{', keep same indentation if possible, insert INSTRUMENT;
                    # add a newline if not present to make the inserted macro on its own line
                    # Find indentation at stmt_start+1
                    m = stmt_start+1
                    # collect any spaces/tabs immediately after '{' up to newline
                    # We'll insert a newline + indentation + macro to avoid breaking formatting
                    # But preserve existing whitespace too
                    # Insert macro now
                    # Determine indentation from previous line
                    # Find column indentation: look backwards for start of line
                    line_start = out and ''.join(out).rfind('\n')
                    if line_start == -1:
                        base_indent = ''
                    else:
                        # base indent = chars after last newline up to '{' position in that source substring
                        base_indent = ''
                        # attempt to detect indentation of next line (conservative)
                    out.append('\n')
                    out.append('INSTRUMENT;')
                    # continue from stmt_start+1
                    i = stmt_start+1
                    continue
                else:
                    # controlled body is a single statement (could be another if) -> wrap it
                    # copy up to stmt_start
                    out.append(s[i:stmt_start])
                    # insert block with INSTRUMENT; then the statement, then close block
                    # find statement end
                    stmt_end = find_statement_end(stmt_start)
                    if stmt_end == -1:
                        stmt_end = N
                    # preserve indentation: determine indent string from original stmt_start
                    # find start of the line containing stmt_start
                    line_begin = s.rfind('\n', 0, stmt_start)
                    if line_begin == -1:
                        line_begin = 0
                    else:
                        line_begin += 1
                    indent = ''
                    p = line_begin
                    while p < stmt_start and s[p] in (' ', '\t'):
                        indent += s[p]; p += 1
                    # Build wrapped block: "{\n<indent>INSTRUMENT;\n<orig stmt>\n<closing indent>}"
                    block = "{\n" + indent + "INSTRUMENT;\n" + s[stmt_start:stmt_end] + "}"
                    out.append(block)
                    i = stmt_end
                    continue
        # otherwise just copy identifier
        out.append(s[i:j])
        i = j
        continue

    # detect top-level function calls printf( or malloc(
    if (s.startswith('printf', i) or s.startswith('malloc', i)):
        # ensure word boundary
        if (i+6 <= N and (i==0 or not is_ident_char(s[i-1]))):
            # find paren after optional spaces
            k = i + (6 if s.startswith('printf', i) else 6)
            # skip any whitespace
            while k < N and s[k].isspace():
                k += 1
            if k < N and s[k] == '(':
                # insert instrumentation on its own line before the call, preserving prev line break if present
                # find start of current line
                line_start = s.rfind('\n', 0, i)
                if line_start == -1:
                    line_start = -1
                # get indentation
                p = line_start + 1
                indent = ''
                while p < i and s[p] in (' ', '\t'):
                    indent += s[p]; p += 1
                out.append(indent + "INSTRUMENT;\n")
                # now continue copying (do not consume here; just let general copy below handle it)
                # but to avoid duplicating the identifier later, just append the identifier now
                # and advance i by len(name)
                if s.startswith('printf', i):
                    out.append('printf')
                    i += 6
                    continue
                else:
                    out.append('malloc')
                    i += 6
                    continue

    # default: copy one character
    out.append(ch)
    i += 1

sys.stdout.write(''.join(out))
PY

