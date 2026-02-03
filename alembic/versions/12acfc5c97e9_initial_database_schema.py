"""Initial database schema

Revision ID: 12acfc5c97e9
Revises: 
Create Date: 2026-02-03 14:21:58.195197

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '12acfc5c97e9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create sessions table
    op.create_table('sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', sa.String(length=100), nullable=False),
        sa.Column('risk_score', sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column('confidence_level', sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column('persona_type', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_turns', sa.Integer(), nullable=False),
        sa.Column('engagement_duration', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('risk_score >= 0.0 AND risk_score <= 1.0', name='valid_risk_score'),
        sa.CheckConstraint('confidence_level >= 0.0 AND confidence_level <= 1.0', name='valid_confidence_level'),
        sa.CheckConstraint('total_turns >= 0', name='non_negative_turns'),
        sa.CheckConstraint('engagement_duration IS NULL OR engagement_duration >= 0', name='non_negative_duration'),
        sa.CheckConstraint("status IN ('active', 'completed', 'terminated')", name='valid_status'),
        sa.CheckConstraint("persona_type IS NULL OR persona_type IN ('digitally_naive', 'average_user', 'skeptical')", name='valid_persona'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id')
    )
    op.create_index('idx_sessions_risk_score', 'sessions', ['risk_score'])
    op.create_index('idx_sessions_status', 'sessions', ['status'])
    op.create_index('idx_sessions_start_time', 'sessions', ['start_time'])
    op.create_index(op.f('ix_sessions_session_id'), 'sessions', ['session_id'], unique=False)

    # Create messages table
    op.create_table('messages',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('language', sa.String(length=10), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('message_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("role IN ('user', 'assistant')", name='valid_role'),
        sa.CheckConstraint("language IN ('en', 'hi', 'hinglish')", name='valid_language'),
        sa.CheckConstraint('LENGTH(content) > 0', name='non_empty_content'),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_messages_session_timestamp', 'messages', ['session_id', 'timestamp'])
    op.create_index('idx_messages_role', 'messages', ['role'])

    # Create extracted_entities table
    op.create_table('extracted_entities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('entity_value', sa.Text(), nullable=False),
        sa.Column('confidence_score', sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column('extraction_method', sa.String(length=50), nullable=True),
        sa.Column('context', sa.Text(), nullable=True),
        sa.Column('verified', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='valid_confidence_score'),
        sa.CheckConstraint("entity_type IN ('upi_id', 'phone_number', 'url', 'bank_account', 'email')", name='valid_entity_type'),
        sa.CheckConstraint('LENGTH(entity_value) > 0', name='non_empty_entity_value'),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_entities_type_confidence', 'extracted_entities', ['entity_type', 'confidence_score'])
    op.create_index('idx_entities_session_type', 'extracted_entities', ['session_id', 'entity_type'])
    op.create_index('idx_entities_verified', 'extracted_entities', ['verified'])

    # Create risk_assessments table
    op.create_table('risk_assessments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('message_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('risk_score', sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column('confidence', sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column('detection_method', sa.String(length=100), nullable=True),
        sa.Column('risk_factors', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('risk_score >= 0.0 AND risk_score <= 1.0', name='valid_risk_score_assessment'),
        sa.CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name='valid_confidence_assessment'),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_risk_assessments_score', 'risk_assessments', ['risk_score'])
    op.create_index('idx_risk_assessments_session', 'risk_assessments', ['session_id'])
    op.create_index('idx_risk_assessments_message', 'risk_assessments', ['message_id'])

    # Create guvi_callbacks table
    op.create_table('guvi_callbacks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('callback_status', sa.String(length=20), nullable=False),
        sa.Column('callback_payload', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False),
        sa.Column('last_attempt', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("callback_status IN ('pending', 'success', 'failed', 'retrying')", name='valid_callback_status'),
        sa.CheckConstraint('retry_count >= 0', name='non_negative_retry_count'),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_guvi_callbacks_status', 'guvi_callbacks', ['callback_status'])
    op.create_index('idx_guvi_callbacks_session', 'guvi_callbacks', ['session_id'])
    op.create_index('idx_guvi_callbacks_last_attempt', 'guvi_callbacks', ['last_attempt'])


def downgrade() -> None:
    # Drop tables in reverse order due to foreign key constraints
    op.drop_table('guvi_callbacks')
    op.drop_table('risk_assessments')
    op.drop_table('extracted_entities')
    op.drop_table('messages')
    op.drop_table('sessions')