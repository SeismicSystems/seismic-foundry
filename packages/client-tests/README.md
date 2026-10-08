# Seismic Viem tests

> Note: the seismic.yml CI is already no longer running these tests because
> of a circular dependency: sanvil CI depends on the seismic-viem TS client
> (to run these tests), but the TS client CI depends on a sanvil binary
> (to test against). When either side makes a breaking change (e.g. adding
> `isCreate` to the EIP-712 schema), neither CI can pass until both repos
> are updated simultaneously.
> 
> **TODO:** Remove this package and migrate tests to the seismic monorepo
> (`seismic/clients/ts/tests/`). The monorepo is the right place for
> integration tests since it controls both the TS client and sanvil versions
> together, avoiding this circular dependency.

To install dependencies:

```bash
bun install
```

To run tests:

```bash
bun test
```
