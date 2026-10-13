"""remove_keep_alive_subsystem

Revision ID: a1e2c3d4e5f6
Revises: 8d3f1a4e2c6b
Create Date: 2026-10-14 01:25:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1e2c3d4e5f6"
down_revision: str | Sequence[str] | None = "8d3f1a4e2c6b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """
    Remove keep-alive subsystem columns, constraints, and indexes.

    Keep-alive is architectural redundancy because standard health monitoring
    already produces active HTTP requests that prevent target services from sleeping.
    """
    # 1. Drop check constraints
    op.drop_constraint("ck_monitors_mode", "monitors", type_="check")
    op.drop_constraint("ck_ping_results_check_type", "ping_results", type_="check")

    # 2. Drop keep-alive index
    op.drop_index("ix_monitors_next_keep_alive_at", table_name="monitors")

    # 3. Drop keep-alive columns from monitors
    op.drop_column("monitors", "next_keep_alive_at")
    op.drop_column("monitors", "keep_alive_path")
    op.drop_column("monitors", "keep_alive_interval_seconds")
    op.drop_column("monitors", "keep_alive_enabled")
    op.drop_column("monitors", "mode")

    # 4. Drop check_type from ping_results
    op.drop_column("ping_results", "check_type")


def downgrade() -> None:
    """Recreate keep-alive subsystem columns, constraints, and indexes."""
    # 1. Re-add check_type to ping_results
    op.add_column(
        "ping_results",
        sa.Column(
            "check_type",
            sa.String(length=20),
            server_default="monitor",
            nullable=False,
        ),
    )

    # 2. Re-add keep-alive columns to monitors
    op.add_column(
        "monitors",
        sa.Column("mode", sa.String(length=30), server_default="monitor", nullable=False),
    )
    op.add_column(
        "monitors",
        sa.Column(
            "keep_alive_enabled",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column(
        "monitors",
        sa.Column("keep_alive_interval_seconds", sa.Integer(), nullable=True),
    )
    op.add_column(
        "monitors",
        sa.Column("keep_alive_path", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "monitors",
        sa.Column("next_keep_alive_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 3. Re-add index
    op.create_index(
        "ix_monitors_next_keep_alive_at",
        "monitors",
        ["next_keep_alive_at"],
        unique=False,
    )

    # 4. Re-add check constraints
    op.create_check_constraint(
        "ck_ping_results_check_type",
        "ping_results",
        "check_type IN ('monitor', 'keep_alive')",
    )
    op.create_check_constraint(
        "ck_monitors_mode",
        "monitors",
        "mode IN ('monitor', 'keep_alive', 'monitor_and_keep_alive')",
    )
