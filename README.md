# pip-surgery ✂️

**Smaller Python environments. Verified against your scenarios.**

A Windows-first tool that aims to identify potentially unused files inside Python dependencies and build a smaller, separate environment — without touching your working one.

## How it will work

1. **Observe** your application across selected scenarios.
2. **Review** potential exclusions and their reasons.
3. **Build** a separate, reduced environment.
4. **Verify** it with your checks and restore files when needed.

## Goals

- One installation through `pip` — no separate monitoring tools.
- File-level analysis inside dependencies.
- Local operation, without APIs or telemetry.
- Explainable decisions and reversible exclusions.

> Unobserved does not mean unnecessary. Passing checks confirms only the scenarios you tested.

## Status

🚧 **Early development — no usable release yet.**

First milestones:
- [ ] Dependency inventory
- [ ] Windows file-observation prototype
- [ ] Read-only exclusion plan
- [ ] Reduced builds, verification, and restoration

**Initial target:** Windows 10/11 x64. Supported Python versions and permission requirements are still being evaluated.

---

*Less disk space. Not a RAM cleaner or a universal speed booster.*
