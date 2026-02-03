"""Add API key authentication tables

Revision ID: add_api_key_tables
Revises: 12acfc5c97e9
Create Date: 2024-12-19 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_api_key_tables'
down_revision = '12acfc5c97e9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create api_keys table
    op.create_table('api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key_name', sa.String(length=100), nullable=False),
        sa.Column('key_hash', sa.LargeBinary(), nullable=False),
        sa.Column('key_prefix', sa.String(length=8), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('permissions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('last_used', sa.DateTime(timezone=True), nullable=True),
        sa.Column('usage_count', sa.Integer(), nullable=False),
        sa.Column('rate_limit_per_hour', sa.Integer(), nullable=False),
        sa.Column('current_hour_usage', sa.Integer(), nullable=False),
        sa.Column('current_hour_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint('rate_limit_per_hour > 0', name='positive_rate_limit'),
        sa.CheckConstraint('usage_count >= 0', name='non_negative_usage_count'),
        sa.CheckConstraint('current_hour_usage >= 0', name='non_negative_hour_usage'),
        sa.CheckConstraint('LENGTH(key_name) > 0', name='non_empty_key_name'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_api_keys_active', 'api_keys', ['is_active'], unique=False)
    op.create_index('idx_api_keys_expires', 'api_keys', ['expires_at'], unique=False)
    op.create_index('idx_api_keys_prefix', 'api_keys', ['key_prefix'], unique=False)

    # Create api_key_usage table
    op.create_table('api_key_usage',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('api_key_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('endpoint', sa.String(length=200), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('client_ip', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('request_size', sa.Integer(), nullable=True),
        sa.Column('response_size', sa.Integer(), nullable=True),
        sa.CheckConstraint("method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')", name='valid_http_method'),
        sa.CheckConstraint('status_code >= 100 AND status_code < 600', name='valid_status_code'),
        sa.CheckConstraint('response_time_ms IS NULL OR response_time_ms >= 0', name='non_negative_response_time'),
        sa.ForeignKeyConstraint(['api_key_id'], ['api_keys.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_api_key_usage_endpoint', 'api_key_usage', ['endpoint'], unique=False)
    op.create_index('idx_api_key_usage_key_timestamp', 'api_key_usage', ['api_key_id', 'request_timestamp'], unique=False)
    op.create_index('idx_api_key_usage_status', 'api_key_usage', ['status_code'], unique=False)
    op.create_index('idx_api_key_usage_timestamp', 'api_key_usage', ['request_timestamp'], unique=False)


def downgrade() -> None:
    # Drop api_key_usage table
    op.drop_index('idx_api_key_usage_timestamp', table_name='api_key_usage')
    op.drop_index('idx_api_key_usage_status', table_name='api_key_usage')
    op.drop_index('idx_api_key_usage_key_timestamp', table_name='api_key_usage')
    op.drop_index('idx_api_key_usage_endpoint', table_name='api_key_usage')
    op.drop_table('api_key_usage')
    
    # Drop api_keys table
    op.drop_index('idx_api_keys_prefix', table_name='api_keys')
    op.drop_index('idx_api_keys_expires', table_name='api_keys')
    op.drop_index('idx_api_keys_active', table_name='api_keys')
    op.drop_table('api_keys')