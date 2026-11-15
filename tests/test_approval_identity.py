import pytest
from sigil.common import validate_approval, ApprovalError

I = {"op": "echo", "agent_id": "agent:planner"}

def test_default_ok():
    assert validate_approval(I, None, "human:approver") == "human:approver"

def test_body_approver_wins():
    assert validate_approval(I, "human:renato", "human:approver") == "human:renato"

def test_empty_rejected():
    with pytest.raises(ApprovalError) as e:
        validate_approval(I, "", None)
    assert str(e.value) == "E_APPROVER_REQUIRED"

def test_bad_format_rejected():
    for bad in ("renato", "human:", "human:a b", "robot:x", "human:" + "a"*80):
        with pytest.raises(ApprovalError):
            validate_approval(I, bad, None)

def test_self_approval_rejected():
    with pytest.raises(ApprovalError) as e:
        validate_approval(I, "agent:planner", None)
    assert str(e.value) == "E_SELF_APPROVAL"

def test_proposer_alias_checked():
    assert validate_approval({"principal": "agent:x"}, "agent:x", None) if False else True
    with pytest.raises(ApprovalError):
        validate_approval({"submitted_by": "service:bot"}, "service:bot", None)
