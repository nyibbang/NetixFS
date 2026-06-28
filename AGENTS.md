# NetixFS Agents Guide

## Development Rules

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```txt
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it
work") require constant clarification.

## Code Style

- Avoid using `unsafe` Rust.
- Follow Rust's standard style (enforced by `cargo fmt`)
- Use `clippy` for linting: `cargo clippy`
- Prefer explicit error handling with `eyre`
- Use `tracing` for logging (not `println!`)
- Always use latest stable versions for new dependencies.
- Avoid using code that may panic (such as `unwrap` or `expect`). Prefer
  explicit error handling and reporting instead.
- Do not suppress errors. At least log them or return them.
- Keep only one crate (`netixfs`) with one executable (binary) in it.
- Always collapse if statements per
  <https://rust-lang.github.io/rust-clippy/master/index.html#collapsible_if>
- Always inline format! args when possible per
  <https://rust-lang.github.io/rust-clippy/master/index.html#uninlined_format_args>
- Use method references over closures when possible per
  <https://rust-lang.github.io/rust-clippy/master/index.html#redundant_closure_for_method_calls>
- Avoid bool or ambiguous Option parameters that force callers to write
  hard-to-read code such as foo(false) or bar(None). Prefer enums, named methods,
  newtypes, or other idiomatic Rust API shapes when they keep the callsite
  self-documenting.
- When possible, make match statements exhaustive and avoid wildcard arms.
- Newly added traits should include doc comments that explain their role and
  how implementations are expected to use them.
- When writing tests, prefer comparing the equality of entire objects over
  fields one by one.
- Do not create small helper methods that are referenced only once.
- Avoid large modules:
  - Prefer adding new modules instead of growing existing ones.
  - Target Rust modules under 500 LoC, excluding tests.
  - If a file exceeds roughly 800 LoC, add new functionality in a new module
    instead of extending the existing file unless there is a strong documented
    reason not to.

## Testing Strategy

Per **SPECS.md Section 15**, testing should cover:

- Path normalization and containment
- Symlink traversal and symlink race scenarios
- JWT validation failures
- Username claim extraction failures
- Local username resolution failures
- POSIX permission behavior
- Read and write operations
- Large directory listings
- Streaming reads
- Concurrent writes and reads
- Error mapping
- Configuration parsing
- Worker process reuse, expiration, and identity isolation
- CORS behavior

Security-sensitive behavior **must** be covered by integration tests on real
Linux filesystems.

## Contributing as an Agent

When contributing to NetixFS:

1. **Read SPECS.md first** - It's the source of truth for all requirements
2. **Follow the implementation plan** - Work on steps in order when possible
3. **Write unit tests** - Especially for security-sensitive functionality.
   Design code so that it is testable, do not rely on I/O such as files or
   network to write tests. Use abstractions if necessary.
4. **Use structured logging** - Include request context in logs
5. **Handle errors properly** - Return structured JSON errors with request IDs
6. **Respect POSIX semantics** - Delegate authorization to the Linux kernel
7. **Keep it simple** - Avoid unnecessary complexity; the spec is already comprehensive

### Common Pitfalls to Avoid

- Hardcoding paths or root directories
- Performing filesystem operations in the supervisor process
- Trusting JWT claims for UID/GID (must resolve via NSS)
- Not validating paths for `..` components or symlink escapes
- Not including request IDs in errors and logs
- Using `CAP_DAC_OVERRIDE` or other broad filesystem capabilities

### Recommended Workflow

1. Identify a task from the implementation plan
2. Read the relevant SPECS.md sections
3. Explore existing code for patterns
4. Implement the feature
5. Write tests (especially integration tests)
6. Verify with `cargo clippy` and `cargo test`
