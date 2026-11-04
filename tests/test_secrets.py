import pytest

from mcp_audit.secrets import MASK, classify, mask_args, token_kind

# Built by concatenation so no complete token-shaped string sits in the source file.
FAKE_GITHUB = "ghp_" + "F" * 36
FAKE_AWS = "AKIA" + "FAKEFAKEFAKEFAKE"


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (FAKE_GITHUB, "github_token"),
        ("Bearer " + FAKE_GITHUB, "github_token"),
        (FAKE_AWS, "aws_access_key_id"),
        ("sk-ant-" + "x" * 30, "anthropic_api_key"),
        ("/Users/taha/notes", None),
        ("-y", None),
    ],
)
def test_token_shapes(value: str, kind: str | None) -> None:
    assert token_kind(value) == kind


@pytest.mark.parametrize("value", ["${GITHUB_TOKEN}", "${env:GITHUB_TOKEN}", "$GITHUB_TOKEN", ""])
def test_references_and_empty_values_are_not_secrets(value: str) -> None:
    assert classify("env:GITHUB_TOKEN", "GITHUB_TOKEN", value) is None


def test_secret_name_with_literal_value_is_a_weaker_hint() -> None:
    hint = classify("env:API_KEY", "API_KEY", "hunter2")
    assert hint is not None
    assert (hint.kind, hint.confidence) == ("secret_name", "name")


def test_ordinary_variable_is_not_a_secret() -> None:
    assert classify("env:LOG_LEVEL", "LOG_LEVEL", "debug") is None


def test_secret_arguments_are_masked() -> None:
    args = ["server", "--api-key", "hunter2", "--token=" + FAKE_GITHUB, FAKE_AWS, "/data"]
    masked, hints = mask_args(args)
    assert masked == ["server", "--api-key", MASK, f"--token={MASK}", MASK, "/data"]
    assert [h.location for h in hints] == ["arg:2", "arg:3", "arg:4"]
    assert "hunter2" not in str(hints)
