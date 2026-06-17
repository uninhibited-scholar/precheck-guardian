import pytest

pytest.importorskip("textual")
pytest.importorskip("pytest_asyncio")

from approval_hook.core.plan_parser import PlanParser  # noqa: E402
from approval_hook.models.approval_record import Decision  # noqa: E402
from approval_hook.ui.tui import ApprovalApp  # noqa: E402

PLAN = PlanParser().parse("1. SELECT * FROM t\n2. rm -rf /tmp/build")


@pytest.mark.asyncio
async def test_tui_renders_all_steps():
    app = ApprovalApp(PLAN)
    async with app.run_test() as pilot:
        table = app.query_one("#steps")
        assert table.row_count == 2
        await pilot.pause()


@pytest.mark.asyncio
async def test_tui_approve_button_returns_approve():
    app = ApprovalApp(PLAN)
    async with app.run_test() as pilot:
        await pilot.click("#approve")
    assert app.return_value is Decision.APPROVE


@pytest.mark.asyncio
async def test_tui_reject_key_returns_reject():
    app = ApprovalApp(PLAN)
    async with app.run_test() as pilot:
        await pilot.press("r")
    assert app.return_value is Decision.REJECT


@pytest.mark.asyncio
async def test_tui_edit_key_returns_edit():
    app = ApprovalApp(PLAN)
    async with app.run_test() as pilot:
        await pilot.press("e")
    assert app.return_value is Decision.EDIT
