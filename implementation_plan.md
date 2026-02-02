# Migration Plan: detailed steps to fix SDK deprecation and rate limiting

## Goal
Replace the deprecated `google-generativeai` package with the new `google-genai` SDK and implement robust retry logic to handle `429 Resource Exhausted` errors.

## Proposed Changes

### 1. Update Dependencies
- [x] Modify `requirements.txt`:
    - Remove `google-generativeai`
    - Add `google-genai`

### 2. Refactor `app/services/llm.py`
- [x] Import `from google import genai` instead of `import google.generativeai`
- [x] Update initialization:
    - Use `client = genai.Client(api_key=...)`
- [x] Update generation call:
    - Use `client.models.generate_content(...)`
- [x] Implement Retry Logic:
    - Add `tenacity` library or custom loop for catching `429` errors.
    - Implementing exponential backoff (1s, 2s, 4s, 8s).

### 3. Verification
- [x] Run `python -m tests.test_integration` to verify the fix.
- [x] Ensure no deprecation warnings in output.

## Verification Plan

### Automated Tests
- Run integration tests:
  ```bash
  python -m tests.test_integration
  ```
- Check console output for "PASS" and absence of "FutureWarning".
