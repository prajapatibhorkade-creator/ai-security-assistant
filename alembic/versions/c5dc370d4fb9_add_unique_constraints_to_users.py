"""add unique constraints to users

Revision ID: c5dc370d4fb9
Revises: d3b3ab32334d
Create Date: 2026-09-20 10:54:29.766927

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c5dc370d4fb9'
down_revision: Union[str, Sequence[str], None] = 'd3b3ab32334d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "email",
            existing_type=sa.VARCHAR(),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "email",
            existing_type=sa.VARCHAR(),
            nullable=True,
        )
