"""add alert status and float risk score

Revision ID: 260e3f800886
Revises: 
Create Date: 2026-09-14 14:51:11.079808

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '260e3f800886'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    column_names = {column["name"] for column in inspector.get_columns("security_alerts")}

    with op.batch_alter_table("security_alerts") as batch_op:
        if "status" not in column_names:
            batch_op.add_column(sa.Column("status", sa.String(), nullable=True))
        if "risk_score" in column_names:
            batch_op.alter_column(
                "risk_score",
                existing_type=sa.INTEGER(),
                type_=sa.Float(),
                existing_nullable=False,
            )


def downgrade() -> None:
    with op.batch_alter_table("security_alerts") as batch_op:
        batch_op.alter_column(
            "risk_score",
            existing_type=sa.Float(),
            type_=sa.INTEGER(),
            existing_nullable=False,
        )
        batch_op.drop_column("status")
