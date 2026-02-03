"""
Tests for the health check endpoint.
"""

import pytest
from datetime import datetime


def test_health_endpoint_returns_200(client):
    """Test that health endpoint returns 200 status code."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_endpoint_response_structure(client):
    """Test that health endpoint returns expected response structure."""
    response = client.get("/health")
    data = response.json()
    
    # Check required fields
    assert "status" in data
    assert "timestamp" in data
    assert "version" in data
    assert "components" in data
    assert "metrics" in data
    
    # Check status is valid
    assert data["status"] in ["healthy", "degraded", "unhealthy"]
    
    # Check components structure
    components = data["components"]
    assert "database" in components
    assert "redis" in components
    assert "llm" in components
    
    # Check metrics structure
    metrics = data["metrics"]
    assert "uptime" in metrics
    assert "requestCount" in metrics
    assert "averageResponseTime" in metrics
    
    # Check timestamp is valid ISO format
    timestamp = data["timestamp"]
    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def test_health_endpoint_no_auth_required(client):
    """Test that health endpoint doesn't require authentication."""
    # Should work without x-api-key header
    response = client.get("/health")
    assert response.status_code == 200


def test_metrics_endpoint_returns_prometheus_format(client):
    """Test that metrics endpoint returns Prometheus format."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    
    # Check for some expected Prometheus metrics
    content = response.text
    assert "http_requests_total" in content or "# HELP" in content