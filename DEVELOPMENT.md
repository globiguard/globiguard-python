# GlobiGuard Python SDK - Development Guide

## CI/CD Pipeline Overview

This repository uses GitHub Actions for automated testing, building, and publishing.

### Workflows

#### 1. **Test & Lint** (`test.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Tests across Python 3.11, 3.12, and 3.13
  - Runs pytest with coverage reporting
  - Reports coverage to Codecov
- **Status check:** ✅ Must pass before merging to `main`

#### 2. **Build & Package** (`build.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Builds wheel and sdist distributions
  - Verifies package integrity
  - Uploads artifacts to GitHub Artifacts (temporary, 5-day retention)
- **Purpose:** Early detection of packaging issues

#### 3. **Publish** (`publish.yml`)
- **Triggers:** When a git tag matching `v*.*.*` is pushed
- **What it does:**
  - Builds distribution packages
  - Publishes to PyPI using `twine`
  - Creates a GitHub Release
- **Requirements:** `PYPI_TOKEN` secret must be configured
- **Usage:**
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

#### 4. **Security Scan** (`security.yml`)
- **Triggers:** Every push to `main`/`develop`, weekly on Sunday
- **What it does:**
  - Runs `pip-audit` for dependency vulnerabilities
  - Runs `bandit` for security issues
  - Runs `safety` checks
- **Purpose:** Continuous security monitoring

### Branch Protection

The `main` branch is protected with:
- ✅ Require 1 pull request review before merging
- ✅ Require all status checks to pass
- ✅ Require branches to be up to date before merging
- ✅ Dismiss stale pull request approvals on new commits
- ✅ Require code owner reviews
- ❌ Force pushes disabled
- ❌ Deletions disabled

### Versioning Strategy

We use **Semantic Versioning** (major.minor.patch):

- **0.1.0** → Initial release
- **0.1.1** → Patch fix (auto-publish on tag)
- **0.2.0** → Minor feature (requires `pyproject.toml` version bump)
- **1.0.0** → Major release (breaking changes)

### Publishing Workflow

#### For Patch Releases (Bug Fixes)
```bash
# 1. Make fixes on a feature branch
git checkout -b fix/issue-123
git commit -m "Fix: issue-123"
git push origin fix/issue-123

# 2. Create PR, get reviewed, merge to main
# (CI/CD tests automatically)

# 3. Tag for release (after merge to main)
git tag v0.1.1
git push origin v0.1.1

# 4. Watch CI/CD publish to PyPI automatically
```

#### For Feature Releases (Minor Bump)
```bash
# 1. Bump version in pyproject.toml
# Change: version = "0.1.0"
# To:     version = "0.2.0"

git checkout -b feat/new-feature
git commit -m "Feat: new-feature"
git commit -m "Bump version to 0.2.0"
git push origin feat/new-feature

# 2. Create PR, review, merge

# 3. Tag and publish
git tag v0.2.0
git push origin v0.2.0
```

### Development Cycle

1. **Create feature branch:** `git checkout -b feature/name main`
2. **Make changes:** Edit code, test locally with `pytest`
3. **Commit:** `git commit -m "Feat: description"`
4. **Push:** `git push origin feature/name`
5. **Create PR:** Open GitHub pull request to `main`
6. **Review:** Automated tests and code review
7. **Merge:** Squash or rebase for clean history
8. **Publish (optional):** Tag release with `git tag v0.X.X`

### Local Testing

```bash
# Install in development mode
pip install -e .

# Run tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ --cov=src/globiguard

# Run linting
python -m py_compile src/globiguard/*.py tests/*.py
```

### Code Owners

Code ownership is defined in `.github/CODEOWNERS`:
- All files: `@globi-explore/maintainers`
- PRs require approval from code owners before merge

### Repository Configuration

- **Default branch:** `main`
- **Discussions:** Enabled (for Q&A)
- **Releases:** Auto-generated from tags
- **Topics:** `globiguard`, `sdk`, `governance`, `python`
- **Visibility:** Public

## Troubleshooting

**Test failures in CI?**
- Check the workflow run logs in GitHub
- Reproduce locally: `python -m pytest tests/`

**PyPI publish fails?**
- Ensure `PYPI_TOKEN` secret is valid
- Check version doesn't already exist on PyPI
- Verify `pyproject.toml` configuration

**Security scan shows issues?**
- Review reported vulnerabilities
- Update dependencies: `pip install --upgrade`
- Address code issues reported by `bandit`

## Questions?

See main repository README or GitHub Discussions for Q&A.
