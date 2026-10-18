# Environment — fair differential (Task 1)

Recorded 2026-10-18 on the machine that ran every result in this folder. Tools live outside
the repos under `~/tools/fair-differential/`; the driver finds them through environment
variables (see `report.md`).

| Component | Version | How installed / verified |
|---|---|---|
| Machine | Apple Silicon (arm64), macOS 27.0.1 | `uname -m`, `sw_vers` |
| .NET SDK | 8.0.131 (runtime Microsoft.NETCore.App 8.0.31) | `brew install dotnet@8`; `dotnet --list-sdks` |
| RESTler | source, commit `6d984deedbc54aad957fa3da0c7e9e5df23a2aee` (2026-02-12, `latest-12-g6d984de`) | `git clone https://github.com/microsoft/restler-fuzzer`; `python3.12 ./build-restler.py --dest_dir ~/tools/fair-differential/restler_bin` → exit 0 |
| RESTler engine Python | 3.12.15 (the engine crashed on 3.14 in worklog 06) | `brew install python@3.12` |
| Java | OpenJDK 17.0.20.1 (Homebrew) | `java -version` |
| EvoMaster | **6.2.0** runnable jar, SHA-256 `93f9c4a0de88b01395d2a1009776aa739973e9f64343778d2fd49c212fd17915` | GitHub release asset `evomaster.jar`; `java -jar evomaster.jar --help` prints `EvoMaster version: 6.2.0` |
| Schemathesis | 4.32.0 | `python3.12 -m venv …; pip install schemathesis` |
| Rust (target + scanner) | rustc 1.99.0, cargo 1.99.0 (Homebrew) | `rustc --version` |

## EvoMaster security / access-control phase: present

EvoMaster's `release_notes.md` (fetched from the GitHub repo):

- **Version 4.0.0**: "For REST, a new security testing phase is executed, to check for access
  control vulnerabilities (e.g., BOLA and BFLA)."
- **Version 5.2.0**: "Several new security oracles have been added, and executed
  automatically after the main fuzzing session is completed."

6.2.0 is the latest release (2026-09-15) and includes both. The option `--security`
("Apply a security testing phase after functional test cases have been generated",
default `true`) is in its `--help`. The fault categories it defines (read from
`com/webfuzzing/commons/faults/DefinedFaultCategory` in the jar) include
`SECURITY_WRONG_AUTHORIZATION` (BOLA/BFLA heuristic), `SECURITY_IGNORE_ANONYMOUS` and
`SECURITY_EXISTENCE_LEAKAGE`.

The task names the paper "Enhancing REST API Fuzzing with Access Policy Violation Checks"
(2026). The release notes do not cite it, so this report does **not** claim 6.2.0 is that
paper's implementation. The claim is only that 6.2.0 ships an access-control security phase.

## Deviations needed to install

- **RESTler SDK pin.** `global.json` in RESTler's repo pins SDK `8.0.414` (`rollForward:
  latestPatch`), and the first build failed: "A compatible .NET SDK was not found …
  Requested SDK version: 8.0.414". Homebrew's `dotnet@8` ships SDK 8.0.131, an older
  feature band of the same .NET 8. In the local clone only, `global.json` was changed to
  `{"sdk": {"version": "8.0.100", "rollForward": "latestFeature"}}`. The second build
  exited 0. RESTler's source is otherwise unmodified.
- **RESTler `python` shim.** RESTler's engine invokes `python`; the host has `python3`.
  The driver puts a `python` → Python 3.12 symlink first on `PATH` (as in worklog 05).
