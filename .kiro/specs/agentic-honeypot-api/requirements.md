# Requirements Document

## Introduction

The Agentic Honeypot API is a sophisticated scam detection and intelligence extraction system designed for the GUVI/HCL AI for Impact Hackathon. The system acts as an intelligent honeypot that detects potential scam attempts, engages scammers through autonomous AI agents, and extracts valuable intelligence while maintaining strict ethical and safety guidelines.

## Glossary

- **Honeypot_System**: The complete API system that detects and engages with potential scammers
- **Scam_Detection_Engine**: Component that analyzes messages for scam indicators and calculates risk scores
- **Autonomous_Agent**: AI-powered conversational agent that engages with detected scammers
- **Intelligence_Extractor**: Component that extracts entities and intelligence from conversations
- **GUVI_Callback_System**: External evaluation system that receives final results
- **Risk_Score**: Numerical value (0.0-1.0) indicating probability of scam attempt
- **Session**: Complete interaction lifecycle from initial message to final callback
- **Entity**: Extracted information like UPI IDs, phone numbers, URLs, bank accounts
- **Persona**: Predefined character type (Digitally Naive, Average User, Skeptical) for agent responses
- **Engagement_Threshold**: Risk score level (0.75) that triggers agent activation
- **Safety_Layer**: Component ensuring ethical compliance and preventing entrapment

## Requirements

### Requirement 1: API Ingress and Authentication

**User Story:** As a system integrator, I want to send messages to the honeypot API with proper authentication, so that the system can process potential scam attempts securely.

#### Acceptance Criteria

1. THE Honeypot_System SHALL expose a POST endpoint at `/api/honeypot` for message processing
2. WHEN a request is received without x-api-key header, THE Honeypot_System SHALL return HTTP 401 Unauthorized
3. WHEN a request is received with invalid x-api-key, THE Honeypot_System SHALL return HTTP 403 Forbidden
4. THE Honeypot_System SHALL expose a GET endpoint at `/health` for system health monitoring
5. WHEN the health endpoint is accessed, THE Honeypot_System SHALL return system status without requiring authentication

### Requirement 2: Message Processing and Validation

**User Story:** As a system operator, I want incoming messages to be properly validated and structured, so that the system can reliably process different message formats.

#### Acceptance Criteria

1. WHEN a message is received, THE Honeypot_System SHALL validate the request schema containing sessionId, message, conversationHistory, and metadata
2. WHEN required fields are missing, THE Honeypot_System SHALL return HTTP 400 Bad Request with descriptive error messages
3. THE Honeypot_System SHALL support messages in English, Hinglish, and Hindi languages
4. WHEN a malformed JSON request is received, THE Honeypot_System SHALL return HTTP 400 Bad Request
5. THE Honeypot_System SHALL normalize and sanitize all input messages before processing

### Requirement 3: Scam Detection and Risk Assessment

**User Story:** As a security analyst, I want the system to accurately detect potential scam attempts and assign risk scores, so that appropriate responses can be triggered.

#### Acceptance Criteria

1. WHEN a message is processed, THE Scam_Detection_Engine SHALL analyze it for scam indicators and calculate a Risk_Score between 0.0 and 1.0
2. THE Scam_Detection_Engine SHALL consider conversation history when calculating risk scores for multi-turn interactions
3. WHEN analyzing messages, THE Scam_Detection_Engine SHALL identify patterns including financial requests, urgency tactics, and social engineering attempts
4. THE Scam_Detection_Engine SHALL assign confidence levels to risk assessments
5. WHEN risk assessment is complete, THE Scam_Detection_Engine SHALL log the decision rationale for audit purposes

### Requirement 4: Agent Activation and Engagement Logic

**User Story:** As a system administrator, I want the system to intelligently decide when to engage with potential scammers, so that resources are used efficiently while maintaining realistic behavior.

#### Acceptance Criteria

1. WHEN Risk_Score exceeds 0.75, THE Honeypot_System SHALL activate the Autonomous_Agent with 80-95% probability
2. WHEN Risk_Score is below 0.75, THE Honeypot_System SHALL respond with a standard non-engaging reply
3. THE Honeypot_System SHALL implement probabilistic engagement to simulate realistic human response patterns
4. WHEN agent activation occurs, THE Honeypot_System SHALL select an appropriate Persona based on message context
5. THE Honeypot_System SHALL never reveal detection status or AI nature to the message sender

### Requirement 5: Autonomous Agent Conversation Management

**User Story:** As a researcher, I want the AI agent to conduct realistic conversations with scammers, so that valuable intelligence can be extracted while maintaining ethical boundaries.

#### Acceptance Criteria

1. THE Autonomous_Agent SHALL generate contextually appropriate responses using Google Gemini LLM
2. THE Autonomous_Agent SHALL maintain conversation state across multiple turns within a session
3. WHEN engaging, THE Autonomous_Agent SHALL adopt one of three personas: Digitally Naive, Average User, or Skeptical
4. THE Autonomous_Agent SHALL aim for 5-10 conversation turns with 80-120 second engagement duration
5. THE Autonomous_Agent SHALL never initiate contact or entrap users into illegal activities
6. THE Autonomous_Agent SHALL terminate conversations that become inappropriate or harmful

### Requirement 6: Intelligence Extraction and Entity Recognition

**User Story:** As a cybersecurity researcher, I want the system to extract valuable intelligence from scammer conversations, so that threat patterns can be analyzed and shared.

#### Acceptance Criteria

1. THE Intelligence_Extractor SHALL identify and extract UPI IDs, phone numbers, URLs, and bank account numbers from conversations
2. WHEN extracting entities, THE Intelligence_Extractor SHALL only report high-confidence extractions to avoid false positives
3. THE Intelligence_Extractor SHALL analyze conversation patterns and extract scammer tactics and methodologies
4. THE Intelligence_Extractor SHALL maintain entity extraction accuracy above 90% for high-confidence predictions
5. THE Intelligence_Extractor SHALL categorize extracted intelligence by threat type and severity

### Requirement 7: Session Lifecycle Management

**User Story:** As a system operator, I want clear session boundaries and lifecycle management, so that conversations are properly tracked and concluded.

#### Acceptance Criteria

1. THE Honeypot_System SHALL create unique sessions for each conversation thread identified by sessionId
2. WHEN a session begins, THE Honeypot_System SHALL initialize conversation state and tracking metadata
3. THE Honeypot_System SHALL maintain session state throughout multi-turn conversations
4. WHEN predetermined engagement criteria are met, THE Honeypot_System SHALL conclude the session
5. THE Honeypot_System SHALL clean up session resources after conclusion and callback completion

### Requirement 8: GUVI Evaluation Integration

**User Story:** As a hackathon evaluator, I want the system to report final results to the GUVI evaluation platform, so that system performance can be assessed.

#### Acceptance Criteria

1. WHEN a session concludes, THE GUVI_Callback_System SHALL send results to https://hackathon.guvi.in/api/updateHoneyPotFinalResult
2. THE GUVI_Callback_System SHALL include sessionId, detectionResult, extractedEntities, conversationSummary, and confidence in the callback payload
3. WHEN the callback fails, THE GUVI_Callback_System SHALL implement retry logic with exponential backoff
4. THE GUVI_Callback_System SHALL log all callback attempts and responses for debugging
5. THE GUVI_Callback_System SHALL never expose detection results to the original message sender

### Requirement 9: Data Persistence and Management

**User Story:** As a system administrator, I want conversation data and intelligence to be properly stored and managed, so that the system can learn and improve over time.

#### Acceptance Criteria

1. THE Honeypot_System SHALL persist all conversations, risk assessments, and extracted intelligence in PostgreSQL database
2. THE Honeypot_System SHALL implement proper database schema with relationships between sessions, messages, and entities
3. WHEN storing sensitive data, THE Honeypot_System SHALL implement appropriate encryption and access controls
4. THE Honeypot_System SHALL maintain data retention policies and cleanup procedures
5. THE Honeypot_System SHALL support database migrations and schema evolution

### Requirement 10: Safety and Ethics Compliance

**User Story:** As a compliance officer, I want the system to operate within ethical and legal boundaries, so that research can be conducted responsibly.

#### Acceptance Criteria

1. THE Safety_Layer SHALL prevent the system from engaging in or encouraging illegal activities
2. THE Safety_Layer SHALL implement content filtering to avoid generating harmful or inappropriate responses
3. WHEN detecting potentially harmful content, THE Safety_Layer SHALL terminate the conversation immediately
4. THE Safety_Layer SHALL ensure the system never entraps users or initiates scam attempts
5. THE Safety_Layer SHALL maintain audit logs of all safety interventions and decisions

### Requirement 11: Performance and Reliability

**User Story:** As a system user, I want the API to respond quickly and reliably, so that real-time scam detection can be effective.

#### Acceptance Criteria

1. THE Honeypot_System SHALL respond to API requests within 2 seconds for 95% of requests
2. THE Honeypot_System SHALL maintain 99.5% uptime during evaluation periods
3. WHEN system load increases, THE Honeypot_System SHALL scale horizontally to maintain performance
4. THE Honeypot_System SHALL implement proper error handling and graceful degradation
5. THE Honeypot_System SHALL monitor system metrics and alert on performance degradation

### Requirement 12: Monitoring and Observability

**User Story:** As a system operator, I want comprehensive monitoring and logging, so that system behavior can be observed and issues can be diagnosed.

#### Acceptance Criteria

1. THE Honeypot_System SHALL implement structured logging for all major system events
2. THE Honeypot_System SHALL expose metrics for detection accuracy, response times, and system health
3. THE Honeypot_System SHALL provide a dashboard for monitoring system performance and statistics
4. WHEN errors occur, THE Honeypot_System SHALL log detailed error information for debugging
5. THE Honeypot_System SHALL implement distributed tracing for request flow analysis