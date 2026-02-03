#!/usr/bin/env python3
"""
Audit Log Analyzer CLI Tool

Command-line interface for searching, analyzing, and generating reports
from comprehensive audit logs.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.audit_search import (
    AuditLogSearcher, SearchQuery, SearchFilter, SearchOperator,
    AuditEventType, AuditSeverity, AggregationQuery
)


def parse_datetime(date_str: str) -> datetime:
    """Parse datetime string in various formats."""
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    raise ValueError(f"Unable to parse datetime: {date_str}")


def create_search_query(args) -> SearchQuery:
    """Create search query from command line arguments."""
    filters = []
    
    # Add filters based on arguments
    if args.risk_score_min:
        filters.append(SearchFilter(
            field="event_data.risk_score",
            operator=SearchOperator.GREATER_EQUAL,
            value=float(args.risk_score_min)
        ))
    
    if args.risk_score_max:
        filters.append(SearchFilter(
            field="event_data.risk_score",
            operator=SearchOperator.LESS_EQUAL,
            value=float(args.risk_score_max)
        ))
    
    if args.detection_method:
        filters.append(SearchFilter(
            field="event_data.detection_method",
            operator=SearchOperator.EQUALS,
            value=args.detection_method
        ))
    
    if args.contains:
        filters.append(SearchFilter(
            field="event_data.decision_rationale",
            operator=SearchOperator.CONTAINS,
            value=args.contains
        ))
    
    # Parse event types
    event_types = None
    if args.event_types:
        event_types = [AuditEventType(et) for et in args.event_types.split(',')]
    
    # Parse severities
    severities = None
    if args.severities:
        severities = [AuditSeverity(s) for s in args.severities.split(',')]
    
    # Parse time range
    start_time = None
    end_time = None
    
    if args.start_date:
        start_time = parse_datetime(args.start_date)
    
    if args.end_date:
        end_time = parse_datetime(args.end_date)
    
    if args.last_hours:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=int(args.last_hours))
    
    if args.last_days:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=int(args.last_days))
    
    return SearchQuery(
        filters=filters,
        start_time=start_time,
        end_time=end_time,
        event_types=event_types,
        severities=severities,
        session_ids=args.session_ids.split(',') if args.session_ids else None,
        limit=args.limit,
        offset=args.offset,
        sort_by=args.sort_by,
        sort_order=args.sort_order
    )


def search_command(args):
    """Execute search command."""
    searcher = AuditLogSearcher()
    query = create_search_query(args)
    
    print(f"Searching audit logs...")
    print(f"Query: {query}")
    
    result = searcher.search(query)
    
    print(f"\nSearch Results:")
    print(f"Total entries found: {result.total_count}")
    print(f"Query time: {result.query_time_ms}ms")
    print(f"Showing {len(result.entries)} entries")
    
    if args.output_format == "json":
        # Output as JSON
        output = {
            "total_count": result.total_count,
            "query_time_ms": result.query_time_ms,
            "entries": [
                {
                    "timestamp": entry.timestamp.isoformat(),
                    "event_id": entry.event_id,
                    "event_type": entry.event_type,
                    "severity": entry.severity,
                    "session_id": entry.session_id,
                    "event_data": entry.event_data,
                    "searchable_fields": entry.searchable_fields
                }
                for entry in result.entries
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        # Output as table
        print("\n" + "="*100)
        for entry in result.entries:
            print(f"Timestamp: {entry.timestamp}")
            print(f"Event ID: {entry.event_id}")
            print(f"Type: {entry.event_type}")
            print(f"Severity: {entry.severity}")
            print(f"Session: {entry.session_id}")
            
            if entry.event_type == "risk_assessment":
                risk_score = entry.event_data.get("risk_score")
                confidence = entry.event_data.get("confidence")
                rationale = entry.event_data.get("decision_rationale", "")
                print(f"Risk Score: {risk_score}")
                print(f"Confidence: {confidence}")
                print(f"Rationale: {rationale[:200]}...")
            
            print("-" * 100)


def aggregate_command(args):
    """Execute aggregate command."""
    searcher = AuditLogSearcher()
    
    # Create aggregation query
    group_by = args.group_by.split(',') if args.group_by else []
    metrics = args.metrics.split(',') if args.metrics else ["count"]
    
    query = AggregationQuery(
        group_by=group_by,
        metrics=metrics
    )
    
    print(f"Aggregating audit logs...")
    print(f"Group by: {group_by}")
    print(f"Metrics: {metrics}")
    
    result = searcher.aggregate(query)
    
    print(f"\nAggregation Results:")
    print(json.dumps(result, indent=2))


def report_command(args):
    """Execute report command."""
    searcher = AuditLogSearcher()
    
    # Parse date range
    start_date = parse_datetime(args.start_date)
    end_date = parse_datetime(args.end_date) if args.end_date else datetime.utcnow()
    
    print(f"Generating compliance report...")
    print(f"Date range: {start_date} to {end_date}")
    print(f"Report type: {args.report_type}")
    
    report = searcher.generate_compliance_report(
        start_date=start_date,
        end_date=end_date,
        report_type=args.report_type
    )
    
    if args.output_file:
        with open(args.output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to: {args.output_file}")
    else:
        print(json.dumps(report, indent=2))


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Audit Log Analyzer - Search and analyze comprehensive audit logs"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search audit logs')
    search_parser.add_argument('--start-date', help='Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    search_parser.add_argument('--end-date', help='End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    search_parser.add_argument('--last-hours', type=int, help='Search last N hours')
    search_parser.add_argument('--last-days', type=int, help='Search last N days')
    search_parser.add_argument('--event-types', help='Comma-separated event types')
    search_parser.add_argument('--severities', help='Comma-separated severities')
    search_parser.add_argument('--session-ids', help='Comma-separated session IDs')
    search_parser.add_argument('--risk-score-min', type=float, help='Minimum risk score')
    search_parser.add_argument('--risk-score-max', type=float, help='Maximum risk score')
    search_parser.add_argument('--detection-method', help='Detection method filter')
    search_parser.add_argument('--contains', help='Search for text in decision rationale')
    search_parser.add_argument('--limit', type=int, default=100, help='Maximum results to return')
    search_parser.add_argument('--offset', type=int, default=0, help='Results offset')
    search_parser.add_argument('--sort-by', default='timestamp', help='Sort field')
    search_parser.add_argument('--sort-order', choices=['asc', 'desc'], default='desc', help='Sort order')
    search_parser.add_argument('--output-format', choices=['table', 'json'], default='table', help='Output format')
    
    # Aggregate command
    agg_parser = subparsers.add_parser('aggregate', help='Aggregate audit logs')
    agg_parser.add_argument('--group-by', help='Comma-separated fields to group by')
    agg_parser.add_argument('--metrics', default='count', help='Comma-separated metrics to calculate')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate compliance report')
    report_parser.add_argument('--start-date', required=True, help='Report start date')
    report_parser.add_argument('--end-date', help='Report end date (default: now)')
    report_parser.add_argument('--report-type', choices=['summary', 'comprehensive'], default='comprehensive', help='Report type')
    report_parser.add_argument('--output-file', help='Output file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'search':
            search_command(args)
        elif args.command == 'aggregate':
            aggregate_command(args)
        elif args.command == 'report':
            report_command(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()