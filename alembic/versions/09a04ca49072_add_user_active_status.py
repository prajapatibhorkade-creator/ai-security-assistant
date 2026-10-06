"""add user active status

Revision ID: 09a04ca49072
Revises: a0174a8ca0b2
Create Date: 2026-09-20 09:45:23.378802

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '09a04ca49072'
down_revision: Union[str, Sequence[str], None] = 'a0174a8ca0b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("alert_status_history") as batch_op:
        batch_op.alter_column(
            "old_status",
            existing_type=sa.VARCHAR(),
            nullable=False,
        )
        batch_op.alter_column(
            "changed_at",
            existing_type=sa.DATETIME(),
            nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("alert_status_history") as batch_op:
        batch_op.alter_column(
            "changed_at",
            existing_type=sa.DATETIME(),
            nullable=False,
        )
        batch_op.alter_column(
            "old_status",
            existing_type=sa.VARCHAR(),
            nullable=True,
        )
