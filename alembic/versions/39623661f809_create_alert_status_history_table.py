"""create alert status history table

Revision ID: 39623661f809
Revises: 260e3f800886
Create Date: 2026-09-19 08:10:41.152878

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '39623661f809'
down_revision: Union[str, Sequence[str], None] = '260e3f800886'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    table_names = inspector.get_table_names()

    if "alert_status_history" not in table_names:
        op.create_table(
            "alert_status_history",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("alert_id", sa.Integer(), nullable=False),
            sa.Column("old_status", sa.String(), nullable=False),
            sa.Column("new_status", sa.String(), nullable=False),
            sa.Column("changed_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_alert_status_history_alert_id",
            "alert_status_history",
            ["alert_id"],
            unique=False,
        )
        op.create_index(
            "ix_alert_status_history_id",
            "alert_status_history",
            ["id"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("alert_status_history")
