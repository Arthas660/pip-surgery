# pip-surgery ✂️

**Smaller Python environments. Built around your application.**

pip-surgery is a Windows-first tool designed to reduce the size of Python environments by identifying potentially unused files inside dependencies.

Instead of removing entire packages, it aims to keep the parts your application needs — verified against the scenarios you test.

## How it works

1. **Observe** — record file usage while running your application.
2. **Review** — inspect potential exclusions and their reasons.
3. **Build** — create a separate, reduced environment.
4. **Verify** — run your checks and restore files when needed.

Your working environment stays untouched.

## Features

- File-level dependency analysis.
- Explainable exclusion plans.
- Separate reduced environments.
- Verification and reversible exclusions.
- JSON reports and repeatable build recipes.

## Project status

🚧 **Under development.** The workflow above describes the intended product, not a completed release.

## Important

Unobserved does not mean unnecessary. A reduced environment is intended for the scenarios you explicitly exercise and verify.

**Less disk space — not a RAM cleaner or a universal speed booster.**
