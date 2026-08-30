import ast
import logging
import subprocess
from pathlib import Path
from typing import Any

from qsma.llm.client import LLMClient
from qsma.utils.models import (
    MigrationStatus,
    ValidationResult,
)
from qsma.validator.state import ValidatorState

logger = logging.getLogger(__name__)


def run_syntax_check(file_paths: list[Path]) -> tuple[bool, str]:
    """Fast syntax check using Python's built-in ast parser."""
    for file_path in file_paths:
        try:
            with open(file_path, encoding="utf-8") as f:
                ast.parse(f.read())
        except SyntaxError as e:
            return False, f"SyntaxError in {file_path}: {e}"
        except Exception as e:
            return False, f"Failed to read/parse {file_path}: {e}"
    return True, ""


def run_test_suite(target_path: Path, timeout: int = 60) -> tuple[bool, str, str]:
    """
    Runs pytest in the target directory.
    Returns (tests_ok: bool, test_summary: str, error_output: str).
    """
    try:
        result = subprocess.run(
            ["pytest", "-x", "--tb=short", str(target_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(target_path),
        )
        tests_ok = result.returncode == 0
        summary = "Tests passed" if tests_ok else "Tests failed"
        error_output = f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}" if not tests_ok else ""
        return tests_ok, summary, error_output
    except subprocess.TimeoutExpired:
        return False, "Test execution timed out", "Timeout"
    except FileNotFoundError:
        logger.info("pytest not found or no tests detected. Skipping test execution.")
        return True, "No tests executed", ""
    except Exception as e:
        return False, "Test execution failed", str(e)


def generate_retry_hints(llm_client: LLMClient, error_output: str, original_snippet: str) -> str:
    """Calls LLM to interpret test/syntax failure and generate actionable hints for the Migrator."""
    prompt = f"""
    You are an expert Python developer debugging a post-quantum cryptography migration.

    The migrator attempted to replace a crypto snippet, but validation failed.

    ORIGINAL SNIPPET:
    {original_snippet}

    VALIDATION ERROR LOG:
    {error_output}

    Provide concise, actionable hints (max 3 bullet points) for the migrator on how to fix the code.
    Focus on missing imports, incorrect API usage for the new PQC library (e.g., liboqs), or type mismatches.
    Do NOT write the full code, just the hints.
    """
    try:
        response = llm_client.chat([{"role": "user", "content": prompt}], max_tokens=300)
        return response.strip()
    except Exception as e:
        logger.error(f"LLM retry hint generation failed: {e}")
        return "Validation failed. Review the error log and ensure PQC library APIs are used correctly."


def validator_node(state: ValidatorState) -> dict[str, Any]:
    """
    LangGraph node: Validates the most recent transformation.
    Returns state updates for LangGraph to route (pass, retry, or escalate).
    """
    finding_id = state.current_finding_id
    if not finding_id:
        logger.warning("Validator called without current_finding_id. Skipping.")
        return {}

    finding = next((f for f in state.findings if f.id == finding_id), None)
    transform_result = next(
        (t for t in state.transformation_results if t.finding_id == finding_id), None
    )

    if not finding or not transform_result:
        logger.error(f"Cannot validate: finding or transform result missing for {finding_id}")
        return {}

    if state.is_dry_run:
        logger.info("Dry-run mode: Skipping actual validation.")
        return {
            "validation_results": state.validation_results
            + [
                ValidationResult(
                    passed=True, build_ok=True, tests_ok=True, test_summary="Dry run skipped"
                )
            ],
            "current_attempt": 0,
            "retry_hints": None,
        }

    logger.info(
        f"Validating migration for {finding_id} (Attempt {state.current_attempt}/{state.max_attempts})"
    )

    # 1. Syntax Check
    files_to_check = (
        transform_result.files_modified
        if transform_result.files_modified
        else [finding.location.file]
    )
    syntax_valid, syntax_error = run_syntax_check(files_to_check)

    if not syntax_valid:
        error_output = syntax_error
        tests_ok = False
        test_summary = "Syntax check failed"
    else:
        # 2. Test Execution
        tests_ok, test_summary, error_output = run_test_suite(state.target_path)

    # 3. Determine Status & Generate Hints if needed
    if syntax_valid and tests_ok:
        logger.info(f"Validation PASSED for {finding_id}")
        validation_result = ValidationResult(
            passed=True, build_ok=True, tests_ok=True, test_summary=test_summary
        )

        # Update finding status to COMPLETED
        updated_findings = [
            f.model_copy(update={"migration_status": MigrationStatus.COMPLETED})
            if f.id == finding_id
            else f
            for f in state.findings
        ]

        return {
            "validation_results": state.validation_results + [validation_result],
            "findings": updated_findings,
            "current_attempt": 0,
            "retry_hints": None,
        }

    # Validation Failed
    if state.current_attempt >= state.max_attempts:
        logger.warning(
            f"Validation FAILED permanently for {finding_id} after {state.max_attempts} attempts."
        )
        validation_result = ValidationResult(
            passed=False,
            build_ok=syntax_valid,
            tests_ok=tests_ok,
            test_summary=test_summary,
            error_output=error_output,
        )

        # Update finding status to FAILED
        updated_findings = [
            f.model_copy(update={"migration_status": MigrationStatus.FAILED})
            if f.id == finding_id
            else f
            for f in state.findings
        ]

        return {
            "validation_results": state.validation_results + [validation_result],
            "findings": updated_findings,
            "current_attempt": 0,
            "retry_hints": None,
        }

    # Retry Path: Generate hints via LLM
    logger.info(f"Validation FAILED for {finding_id}. Generating retry hints...")
    llm_client = LLMClient()
    original_snippet = finding.location.snippet or transform_result.original_snippet or ""
    retry_hints = generate_retry_hints(llm_client, error_output, original_snippet)

    validation_result = ValidationResult(
        passed=False,
        build_ok=syntax_valid,
        tests_ok=tests_ok,
        test_summary=test_summary,
        error_output=error_output,
    )

    return {
        "validation_results": state.validation_results + [validation_result],
        "current_attempt": state.current_attempt + 1,
        "retry_hints": retry_hints,
    }
