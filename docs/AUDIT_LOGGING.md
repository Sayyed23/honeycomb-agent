# Comprehensive Audit Logging System

## Overview

The Agentic Honeypot API implements a comprehensive audit logging system that tracks all risk assessment decisions, their rationale, and contributing factors. This system ensures full compliance with Requirements 3.5 and provides detailed audit trails for all system operations.

## Features

### 1. Structured Risk Assessment Logging
- **Decision Rationale**: Human-readable explanations for every risk assessment decision
- **Contributing Factors**: Detailed breakdown of all factors that influenced the risk score
- **Analysis Components**: Individual scores from rule-based, keyword, pattern, contextual, and ML analysis
- **Temporal Patterns**: Analysis of conversation timing and flow patterns
- **Cross-Session Patterns**: Detection of patterns across multiple sessions

### 2. Comprehensive Event Tracking
- **Risk Assessments**: Every message analysis with full decision context
- **Agent Activations**: All agent activation decisions with probability calculations
- **Entity Extractions**: Intelligence extraction operations with confidence scores
- **Safety Interventions**: All safety-related actions and their triggers
- **System Errors**: Detailed error tracking with context and recovery actions

### 3. Searchable and Aggregatable Logs
- **Advanced Search**: Complex queries with multiple filters and operators
- **Aggregations**: Statistical analysis and reporting capabilities
- **Compliance Reports**: Automated generation of compliance and audit reports
- **Real-time Analysis**: Live monitoring and alerting capabilities

## Architecture

### Core Components

#### AuditLogger (`app/core/audit_logger.py`)
The main audit logging interface that provides structured logging for all system operations.

```python
from app.core.audit_logger import audit_logger

# Log a risk assessment
event_id = audit_logger.log_risk_assessment(
    session_id="session-001",
    message_id="msg-001",
    risk_score=0.85,
    confidence=0.92,
    detection_method="combined",
    risk_factors=["financial_keywords_3", "urgency_indicators_2"],
    contributing_factors={...},
    analysis_breakdown={...},
    conversation_context={...}
)
```

#### AuditLogSearcher (`app/core/audit_search.py`)
Advanced search and aggregation engine for audit logs.

```python
from app.core.audit_search import audit_searcher, SearchQuery, SearchFilter

# Search for high-risk assessments
query = SearchQuery(
    filters=[
        SearchFilter(
            field="event_data.risk_score",
            operator=SearchOperator.GREATER_THAN,
            value=0.8
        )
    ],
    event_types=[AuditEventType.RISK_ASSESSMENT],
    limit=100
)

results = audit_searcher.search(query)
```

### Event Types

1. **RISK_ASSESSMENT**: Risk analysis decisions
2. **AGENT_ACTIVATION**: Agent activation decisions
3. **ENTITY_EXTRACTION**: Intelligence extraction operations
4. **SAFETY_INTERVENTION**: Safety-related actions
5. **SYSTEM_ERROR**: Error conditions and recovery
6. **AUTHENTICATION**: Authentication events
7. **RATE_LIMITING**: Rate limiting actions

### Severity Levels

- **LOW**: Routine operations, low-risk assessments
- **MEDIUM**: Moderate risk assessments, standard operations
- **HIGH**: High-risk assessments, agent activations, system errors
- **CRITICAL**: Safety interventions, critical system failures

## Usage Examples

### 1. Risk Assessment Logging

The system automatically logs every risk assessment with comprehensive details:

```python
# This happens automatically in ScamDetectionEngine.calculate_risk_score()
assessment = engine.analyze_message(message, history, metadata)

# Comprehensive audit logging
audit_logger.log_risk_assessment(
    session_id=metadata.get('session_id'),
    risk_score=assessment.risk_score,
    confidence=assessment.confidence,
    detection_method=assessment.detection_method.value,
    risk_factors=assessment.risk_factors,
    contributing_factors={
        'analysis_components': {
            'rule_based': assessment.details.get('rule_based_score'),
            'keyword_analysis': assessment.details.get('keyword_score'),
            'pattern_matching': assessment.details.get('pattern_score'),
            'contextual_analysis': assessment.details.get('context_score'),
            'ml_classification': assessment.details.get('ml_score')
        },
        'risk_factor_categories': categorized_factors,
        'confidence_factors': confidence_analysis,
        'temporal_analysis': temporal_patterns,
        'conversation_flow': flow_analysis
    },
    analysis_breakdown=assessment.details,
    conversation_context=context_info,
    ml_prediction=assessment.ml_prediction
)
```

### 2. Searching Audit Logs

```python
from app.core.audit_search import audit_searcher, SearchQuery, SearchFilter, SearchOperator
from datetime import datetime, timedelta

# Search for high-risk assessments in the last 24 hours
query = SearchQuery(
    filters=[
        SearchFilter(
            field="event_data.risk_score",
            operator=SearchOperator.GREATER_EQUAL,
            value=0.75
        ),
        SearchFilter(
            field="event_data.detection_method",
            operator=SearchOperator.EQUALS,
            value="combined"
        )
    ],
    start_time=datetime.utcnow() - timedelta(hours=24),
    event_types=[AuditEventType.RISK_ASSESSMENT],
    severities=[AuditSeverity.HIGH],
    limit=50
)

results = audit_searcher.search(query)
print(f"Found {results.total_count} high-risk assessments")

for entry in results.entries:
    print(f"Session: {entry.session_id}")
    print(f"Risk Score: {entry.event_data['risk_score']}")
    print(f"Rationale: {entry.event_data['decision_rationale']}")
```

### 3. Generating Compliance Reports

```python
from datetime import datetime, timedelta

# Generate weekly compliance report
start_date = datetime.utcnow() - timedelta(days=7)
end_date = datetime.utcnow()

report = audit_searcher.generate_compliance_report(
    start_date=start_date,
    end_date=end_date,
    report_type="comprehensive"
)

print(f"Total events: {report['summary_statistics']['total_events']}")
print(f"Risk assessments: {report['risk_assessment_analysis']['total_assessments']}")
print(f"Average risk score: {report['risk_assessment_analysis']['average_risk_score']:.3f}")
```

### 4. Aggregating Data

```python
from app.core.audit_search import AggregationQuery

# Aggregate risk assessments by detection method
agg_query = AggregationQuery(
    group_by=["event_data.detection_method"],
    metrics=["count", "risk_score_avg"]
)

results = audit_searcher.aggregate(agg_query)
print("Risk assessments by detection method:")
for method, count in results["count"].items():
    avg_score = results["risk_score_avg"].get(method, 0)
    print(f"  {method}: {count} assessments, avg score: {avg_score:.3f}")
```

## Command Line Interface

The system includes a comprehensive CLI tool for searching and analyzing audit logs:

```bash
# Search for high-risk assessments in the last 24 hours
python scripts/audit_log_analyzer.py search \
    --last-hours 24 \
    --risk-score-min 0.75 \
    --event-types risk_assessment \
    --output-format json

# Generate a compliance report for the last week
python scripts/audit_log_analyzer.py report \
    --start-date 2024-01-01 \
    --end-date 2024-01-07 \
    --report-type comprehensive \
    --output-file weekly_report.json

# Aggregate data by detection method
python scripts/audit_log_analyzer.py aggregate \
    --group-by event_data.detection_method \
    --metrics count,risk_score_avg
```

### CLI Commands

#### Search Command
```bash
audit_log_analyzer.py search [OPTIONS]

Options:
  --start-date TEXT          Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
  --end-date TEXT            End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
  --last-hours INTEGER       Search last N hours
  --last-days INTEGER        Search last N days
  --event-types TEXT         Comma-separated event types
  --severities TEXT          Comma-separated severities
  --session-ids TEXT         Comma-separated session IDs
  --risk-score-min FLOAT     Minimum risk score
  --risk-score-max FLOAT     Maximum risk score
  --detection-method TEXT    Detection method filter
  --contains TEXT            Search for text in decision rationale
  --limit INTEGER            Maximum results to return (default: 100)
  --offset INTEGER           Results offset (default: 0)
  --sort-by TEXT             Sort field (default: timestamp)
  --sort-order [asc|desc]    Sort order (default: desc)
  --output-format [table|json] Output format (default: table)
```

#### Report Command
```bash
audit_log_analyzer.py report [OPTIONS]

Options:
  --start-date TEXT          Report start date (required)
  --end-date TEXT            Report end date (default: now)
  --report-type [summary|comprehensive] Report type (default: comprehensive)
  --output-file TEXT         Output file path
```

#### Aggregate Command
```bash
audit_log_analyzer.py aggregate [OPTIONS]

Options:
  --group-by TEXT            Comma-separated fields to group by
  --metrics TEXT             Comma-separated metrics to calculate (default: count)
```

## Log Structure

### Risk Assessment Log Entry
```json
{
  "audit_event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "risk_assessment",
  "severity": "high",
  "timestamp": "2024-01-15T10:30:00Z",
  "session_id": "session-001",
  "correlation_id": "corr-001",
  "processing_time_ms": 150,
  "event_data": {
    "session_id": "session-001",
    "message_id": "msg-001",
    "risk_score": 0.85,
    "confidence": 0.92,
    "detection_method": "combined",
    "risk_factors": [
      "financial_keywords_3",
      "urgency_indicators_2",
      "ml_high_scam_probability"
    ],
    "contributing_factors": {
      "analysis_components": {
        "rule_based": 0.4,
        "keyword_analysis": 0.3,
        "pattern_matching": 0.2,
        "contextual_analysis": 0.1,
        "ml_classification": 0.5
      },
      "risk_factor_categories": {
        "financial": ["financial_keywords_3"],
        "urgency": ["urgency_indicators_2"],
        "ml_indicators": ["ml_high_scam_probability"]
      },
      "confidence_factors": {
        "ml_agreement": true,
        "multiple_indicators": true,
        "contextual_support": true
      }
    },
    "decision_rationale": "HIGH RISK (score: 0.85) - Strong indicators of scam attempt detected. High confidence (0.92) in assessment. Key risk factors: financial_keywords_3, urgency_indicators_2, ml_high_scam_probability. Significant analysis components: Rule Based (0.40), Keyword Analysis (0.30), Ml Classification (0.50). ML model indicates 0.50 probability of scam.",
    "rule_based_score": 0.4,
    "keyword_score": 0.3,
    "pattern_score": 0.2,
    "context_score": 0.1,
    "ml_score": 0.5,
    "conversation_turn": 3,
    "message_length": 150,
    "language": "en",
    "ml_prediction": {
      "probability": 0.87,
      "confidence": 0.91,
      "model_predictions": {
        "random_forest": 0.89,
        "svm": 0.85,
        "naive_bayes": 0.88
      },
      "top_features": {
        "financial_score": 0.45,
        "urgency_score": 0.32
      }
    }
  },
  "searchable_fields": {
    "event_type": "risk_assessment",
    "severity": "high",
    "session_id": "session-001",
    "risk_score": 0.85,
    "confidence": 0.92,
    "detection_method": "combined",
    "risk_factors": ["financial_keywords_3", "urgency_indicators_2"],
    "language": "en",
    "conversation_turn": 3
  }
}
```

## Compliance and Security

### Data Retention
- **Audit logs**: Retained for 2 years for compliance and analysis
- **Personal data**: Anonymized after 90 days
- **System logs**: Retained for 30 days for debugging

### Access Control
- **Read access**: Authorized personnel only
- **Search capabilities**: Role-based access control
- **Export functions**: Audit trail for all data exports

### Privacy Protection
- **Data anonymization**: Personal identifiers removed from long-term storage
- **Encryption**: All audit data encrypted at rest and in transit
- **Access logging**: All audit log access is itself audited

## Performance Considerations

### Logging Performance
- **Asynchronous logging**: Non-blocking audit operations
- **Batch processing**: Efficient bulk log processing
- **Indexing**: Optimized search performance with proper indexing

### Storage Optimization
- **Compression**: Log compression for long-term storage
- **Archiving**: Automated archiving of old audit data
- **Cleanup**: Automated cleanup of expired logs

### Search Performance
- **Indexing strategy**: Optimized indexes for common search patterns
- **Caching**: Search result caching for frequently accessed data
- **Pagination**: Efficient pagination for large result sets

## Monitoring and Alerting

### Real-time Monitoring
- **High-risk patterns**: Automatic alerts for unusual risk patterns
- **System errors**: Immediate notification of critical errors
- **Performance degradation**: Alerts for slow audit operations

### Compliance Monitoring
- **Audit coverage**: Ensure all operations are properly audited
- **Data integrity**: Verify audit log completeness and accuracy
- **Retention compliance**: Monitor data retention policy compliance

## Integration Points

### Scam Detection Engine
- Automatic audit logging for all risk assessments
- Detailed decision rationale generation
- Performance metrics tracking

### Agent Orchestration
- Agent activation decision logging
- Persona selection rationale
- Engagement probability calculations

### Safety Systems
- Safety intervention logging
- Content filtering decisions
- Escalation triggers

### GUVI Callback System
- Callback attempt logging
- Success/failure tracking
- Retry logic auditing

## Testing

The audit logging system includes comprehensive tests:

```bash
# Run audit logging tests
pytest tests/test_audit_logging.py -v

# Run integration tests
pytest tests/test_audit_integration.py -v

# Run performance tests
pytest tests/test_audit_performance.py -v
```

## Future Enhancements

### Planned Features
1. **Real-time dashboards**: Live monitoring and visualization
2. **Machine learning analysis**: Automated pattern detection in audit logs
3. **Advanced alerting**: Configurable alert rules and notifications
4. **API integration**: REST API for external audit log access
5. **Export formats**: Support for additional export formats (CSV, XML)

### Scalability Improvements
1. **Distributed logging**: Support for distributed audit log storage
2. **Stream processing**: Real-time audit log processing and analysis
3. **Cloud integration**: Native cloud storage and search integration
4. **Microservices**: Dedicated audit service for large deployments

## Troubleshooting

### Common Issues

#### Audit Logs Not Appearing
1. Check logger configuration in `app/core/logging.py`
2. Verify audit logger initialization
3. Check log level settings
4. Verify disk space and permissions

#### Search Performance Issues
1. Check index configuration
2. Optimize search queries
3. Consider result pagination
4. Monitor system resources

#### Missing Audit Data
1. Verify all integration points are properly configured
2. Check for exceptions in audit logging code
3. Review error logs for audit failures
4. Validate data retention policies

### Debug Mode
Enable debug logging for detailed audit system information:

```python
import logging
logging.getLogger('audit').setLevel(logging.DEBUG)
```

## Support

For questions or issues with the audit logging system:

1. Check the troubleshooting section above
2. Review the test cases for usage examples
3. Examine the source code documentation
4. Contact the development team for assistance

## Changelog

### Version 1.0.0 (Initial Release)
- Comprehensive risk assessment audit logging
- Advanced search and aggregation capabilities
- CLI tools for log analysis
- Compliance reporting features
- Integration with scam detection engine
- Performance optimization and monitoring
