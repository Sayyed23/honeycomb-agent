# Agentic Honeypot API

A sophisticated scam detection and intelligence extraction system designed for the GUVI/HCL AI for Impact Hackathon. The system acts as an intelligent honeypot that detects potential scam attempts, engages scammers through autonomous AI agents, and extracts valuable intelligence while maintaining strict ethical and safety guidelines.

## Features

- **Advanced Scam Detection**: Multi-layered detection using rule-based filters and ML models
- **Intelligent Agent Engagement**: Context-aware AI agents with realistic persona-based responses
- **Intelligence Extraction**: Automated extraction of threat indicators and scammer tactics
- **Ethical Operation**: Robust safety framework preventing entrapment and harmful activities
- **Production Ready**: Scalable architecture with comprehensive monitoring and reliability features

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker and Docker Compose (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd agentic-honeypot-api
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the database**
   ```bash
   # Create database and run migrations
   alembic upgrade head
   ```

5. **Run the application**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop services
docker-compose down
```

## API Endpoints

### Health Check
```
GET /health
```
Returns system health status and metrics.

### Main Honeypot Endpoint
```
POST /api/honeypot
```
Processes potential scam messages and returns appropriate responses.

**Request Headers:**
- `x-api-key`: Required API key for authentication

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": "Message content to analyze",
  "conversationHistory": [
    {
      "role": "user",
      "content": "Previous message",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ],
  "metadata": {
    "language": "en",
    "userAgent": "Mozilla/5.0...",
    "ipAddress": "192.168.1.1"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "System response message",
  "sessionId": "unique-session-id",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Metrics
```
GET /metrics
```
Returns Prometheus metrics for monitoring.

## Configuration

The application uses environment variables for configuration. Key settings include:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `GEMINI_API_KEY`: Google Gemini API key
- `API_KEY_SECRET`: Secret for API key validation
- `GUVI_CALLBACK_URL`: GUVI evaluation endpoint
- `SCAM_RISK_THRESHOLD`: Risk threshold for agent activation (default: 0.75)

See `.env.example` for all available configuration options.

## Architecture

The system follows a layered architecture with clear separation of concerns:

- **API Gateway Layer**: Handles authentication, request validation, and response formatting
- **Scam Detection Engine**: Analyzes messages using ML models and rule-based systems
- **Agent Orchestration**: Manages agent activation, persona selection, and conversation lifecycle
- **Conversation Engine**: Maintains multi-turn conversation state and generates responses
- **Intelligence Extraction**: Identifies and extracts entities and threat intelligence
- **Safety & Compliance**: Ensures ethical operation and prevents harmful interactions

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run property-based tests
pytest tests/property_tests/ -v
```

### Code Quality

```bash
# Format code
black app/ tests/

# Sort imports
isort app/ tests/

# Lint code
flake8 app/ tests/

# Type checking
mypy app/

# Security scan
bandit -r app/
safety check
```

### Database Migrations

```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## Deployment

### Railway

1. Connect your repository to Railway
2. Set environment variables in Railway dashboard
3. Deploy automatically on push to main branch

### Google Cloud Run

1. Build and push Docker image:
   ```bash
   docker build -t gcr.io/PROJECT_ID/agentic-honeypot-api .
   docker push gcr.io/PROJECT_ID/agentic-honeypot-api
   ```

2. Deploy to Cloud Run:
   ```bash
   gcloud run deploy agentic-honeypot-api \
     --image gcr.io/PROJECT_ID/agentic-honeypot-api \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated
   ```

## Monitoring

The application exposes Prometheus metrics at `/metrics` endpoint. Key metrics include:

- Request count and duration
- Scam detection accuracy
- Active sessions
- LLM API calls
- System health status

## Security

- API key authentication for all protected endpoints
- Input validation and sanitization
- Rate limiting
- Security headers
- Encrypted data storage
- Comprehensive audit logging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is developed for the GUVI/HCL AI for Impact Hackathon.

## Support

For questions or issues, please contact the development team or create an issue in the repository.