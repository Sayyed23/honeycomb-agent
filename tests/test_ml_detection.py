"""
Tests for the ML-based scam detection system.
"""

import pytest
import numpy as np
from typing import List, Dict, Any

from app.core.ml_detection import (
    TextPreprocessor, FeatureEngineer, EnsembleScamClassifier, 
    MLScamDetector, MLPrediction
)
from app.core.scam_detection import ScamDetectionEngine


class TestTextPreprocessor:
    """Test cases for the TextPreprocessor."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.preprocessor = TextPreprocessor()
    
    def test_text_cleaning(self):
        """Test text cleaning functionality."""
        test_cases = [
            {
                "input": "URGENT! Send money to 9876543210 via UPI test@paytm immediately!!!",
                "expected_patterns": ["urgent", "send", "money", "phone", "upi", "immedi", "exclam"]
            },
            {
                "input": "Visit https://suspicious-site.com for details",
                "expected_patterns": ["visit", "url", "detail"]
            },
            {
                "input": "Contact me at email@domain.com",
                "expected_patterns": ["contact", "email"]
            }
        ]
        
        for case in test_cases:
            result = self.preprocessor.preprocess(case["input"])
            processed_text = result['processed_text'].lower()
            
            for pattern in case["expected_patterns"]:
                assert pattern in processed_text, f"Pattern '{pattern}' not found in processed text: {processed_text}"
    
    def test_tokenization(self):
        """Test tokenization functionality."""
        text = "Hello world! How are you today?"
        result = self.preprocessor.preprocess(text)
        
        assert isinstance(result['tokens'], list)
        assert len(result['tokens']) > 0
        assert all(isinstance(token, str) for token in result['tokens'])
    
    def test_language_specific_processing(self):
        """Test language-specific processing."""
        # Test Hinglish
        hinglish_preprocessor = TextPreprocessor(language='hinglish')
        text = "Paisa jaldi bhejo yaar"
        result = hinglish_preprocessor.preprocess(text)
        
        assert 'paisa' in result['processed_text'] or 'pais' in result['processed_text']
    
    def test_empty_text_handling(self):
        """Test handling of empty or None text."""
        result = self.preprocessor.preprocess("")
        assert result['processed_text'] == ""
        assert result['tokens'] == []
        
        result = self.preprocessor.preprocess(None)
        assert result['processed_text'] == ""


class TestFeatureEngineer:
    """Test cases for the FeatureEngineer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.feature_engineer = FeatureEngineer(max_features=100)  # Small for testing
    
    def test_custom_feature_extraction(self):
        """Test custom feature extraction."""
        test_cases = [
            {
                "text": "URGENT! Send money to 9876543210 immediately!!!",
                "expected_features": {
                    "urgency_score": lambda x: x > 0,
                    "financial_score": lambda x: x > 0,
                    "phone_number_present": lambda x: x == 1.0,
                    "exclamation_count": lambda x: x > 0
                }
            },
            {
                "text": "Hello, how are you today?",
                "expected_features": {
                    "urgency_score": lambda x: x == 0,
                    "financial_score": lambda x: x == 0,
                    "phone_number_present": lambda x: x == 0.0
                }
            }
        ]
        
        for case in test_cases:
            features = self.feature_engineer.extract_custom_features(case["text"])
            
            for feature_name, condition in case["expected_features"].items():
                assert feature_name in features, f"Feature '{feature_name}' not found"
                assert condition(features[feature_name]), f"Feature '{feature_name}' failed condition: {features[feature_name]}"
    
    def test_fit_transform(self):
        """Test fit and transform functionality."""
        sample_texts = [
            "Send money urgently to bank account",
            "Hello how are you today",
            "Trust me I am bank officer give PIN",
            "Weather is nice today"
        ]
        
        # Test fit_transform
        features = self.feature_engineer.fit_transform(sample_texts)
        
        assert features.shape[0] == len(sample_texts)
        assert features.shape[1] > 0
        assert isinstance(features, np.ndarray)
    
    def test_feature_names(self):
        """Test feature name generation."""
        sample_texts = [
            "test message with more words",
            "another test with different content",
            "third sample text for testing",
            "fourth message to ensure enough data"
        ]  # More samples to avoid TF-IDF issues
        self.feature_engineer.fit_transform(sample_texts)
        
        feature_names = self.feature_engineer.get_feature_names()
        assert len(feature_names) > 0
        assert all(isinstance(name, str) for name in feature_names)
    
    def test_transform_without_fit(self):
        """Test that transform fails without fit."""
        with pytest.raises(ValueError, match="must be fitted"):
            self.feature_engineer.transform(["test"])


class TestEnsembleScamClassifier:
    """Test cases for the EnsembleScamClassifier."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.classifier = EnsembleScamClassifier()
        
        # Create sample training data
        np.random.seed(42)
        self.X_train = np.random.rand(50, 20)  # 50 samples, 20 features
        self.y_train = np.random.randint(0, 2, 50)  # Binary labels
    
    def test_fit_and_predict(self):
        """Test fitting and prediction."""
        # Fit the classifier
        self.classifier.fit(self.X_train, self.y_train)
        assert self.classifier.is_fitted
        
        # Test prediction
        X_test = np.random.rand(5, 20)
        predictions = self.classifier.predict_proba(X_test)
        
        assert predictions.shape == (5, 2)
        assert np.all(predictions >= 0) and np.all(predictions <= 1)
        assert np.allclose(predictions.sum(axis=1), 1.0)
    
    def test_individual_predictions(self):
        """Test individual model predictions."""
        self.classifier.fit(self.X_train, self.y_train)
        
        X_test = np.random.rand(3, 20)
        individual_preds = self.classifier.get_individual_predictions(X_test)
        
        assert isinstance(individual_preds, dict)
        assert len(individual_preds) > 0
        
        for model_name, preds in individual_preds.items():
            assert len(preds) == 3
            assert np.all(preds >= 0) and np.all(preds <= 1)
    
    def test_confidence_calculation(self):
        """Test confidence calculation."""
        # Test with high confidence predictions
        high_conf_probs = np.array([[0.1, 0.9], [0.05, 0.95]])
        confidence = self.classifier.calculate_confidence(high_conf_probs)
        assert np.all(confidence > 0.5)
        
        # Test with low confidence predictions
        low_conf_probs = np.array([[0.45, 0.55], [0.48, 0.52]])
        confidence = self.classifier.calculate_confidence(low_conf_probs)
        assert np.all(confidence < 0.5)
    
    def test_evaluation(self):
        """Test model evaluation."""
        self.classifier.fit(self.X_train, self.y_train)
        
        X_test = self.X_train[:10]  # Use subset of training data
        y_test = self.y_train[:10]
        
        evaluation = self.classifier.evaluate(X_test, y_test)
        
        assert 'accuracy' in evaluation
        assert 'cv_mean' in evaluation
        assert 'cv_std' in evaluation
        assert 'classification_report' in evaluation
        assert 'confusion_matrix' in evaluation
        
        assert 0 <= evaluation['accuracy'] <= 1


class TestMLScamDetector:
    """Test cases for the complete MLScamDetector."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = MLScamDetector()
    
    def test_training_data_creation(self):
        """Test synthetic training data creation."""
        texts, labels = self.detector.create_training_data()
        
        assert len(texts) == len(labels)
        assert len(texts) > 40  # Should have expanded dataset
        assert all(isinstance(text, str) for text in texts)
        assert all(label in [0, 1] for label in labels)
        assert sum(labels) > 0  # Should have some positive examples
        assert sum(labels) < len(labels)  # Should have some negative examples
    
    def test_prediction_without_training(self):
        """Test prediction when model is not trained."""
        prediction = self.detector.predict("Test message")
        
        assert isinstance(prediction, MLPrediction)
        assert 0 <= prediction.probability <= 1
        assert 0 <= prediction.confidence <= 1
        assert isinstance(prediction.model_predictions, dict)
        assert isinstance(prediction.feature_importance, dict)
    
    def test_training_and_prediction(self):
        """Test training and subsequent prediction."""
        # Train with synthetic data
        training_results = self.detector.train_with_synthetic_data()
        
        assert 'train_metrics' in training_results
        assert 'test_metrics' in training_results
        assert self.detector.is_trained
        
        # Test prediction after training
        prediction = self.detector.predict("URGENT! Send money immediately!")
        
        assert isinstance(prediction, MLPrediction)
        assert prediction.probability > 0.5  # Should detect as scam
        assert len(prediction.model_predictions) > 0
    
    def test_prediction_with_conversation_history(self):
        """Test prediction with conversation history."""
        if not self.detector.is_trained:
            self.detector.train_with_synthetic_data()
        
        history = [
            "Hello, I need help",
            "I am from bank customer service",
            "Your account has suspicious activity"
        ]
        
        prediction = self.detector.predict("Send OTP immediately", history)
        
        assert isinstance(prediction, MLPrediction)
        # Should have higher risk due to conversation context
        assert prediction.probability > 0.3


class TestMLIntegrationWithScamDetectionEngine:
    """Test ML integration with the main ScamDetectionEngine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = ScamDetectionEngine()
    
    def test_ml_integration_in_risk_assessment(self):
        """Test that ML predictions are integrated into risk assessment."""
        message = "URGENT! Bank account blocked. Send OTP to verify immediately."
        
        assessment = self.engine.analyze_message(message, [], {})
        
        # Should have ML prediction in the assessment
        assert assessment.ml_prediction is not None
        assert 'probability' in assessment.ml_prediction
        assert 'confidence' in assessment.ml_prediction
        assert 'model_predictions' in assessment.ml_prediction
    
    def test_ml_risk_factors(self):
        """Test that ML-specific risk factors are included."""
        message = "I am bank officer. Give me your PIN number immediately."
        
        assessment = self.engine.analyze_message(message, [], {})
        
        # Should have ML-related risk factors
        ml_factors = [factor for factor in assessment.risk_factors if factor.startswith('ml_')]
        assert len(ml_factors) > 0
    
    def test_high_risk_detection_with_ml(self):
        """Test high-risk detection with ML enhancement."""
        high_risk_messages = [
            "URGENT! Your bank account will be blocked. Send OTP immediately.",
            "I am bank manager. Your account has suspicious activity. Give PIN.",
            "Emergency! Send money to 9876543210. Trust me, I am officer."
        ]
        
        for message in high_risk_messages:
            assessment = self.engine.analyze_message(message, [], {})
            
            # Should detect as high risk (>= 0.75)
            assert assessment.risk_score >= 0.75, f"Message should be high risk: {message} (score: {assessment.risk_score})"
    
    def test_low_risk_detection_with_ml(self):
        """Test low-risk detection with ML enhancement."""
        low_risk_messages = [
            "Hello, how are you doing today?",
            "The weather is really nice outside.",
            "Thank you for your help yesterday."
        ]
        
        for message in low_risk_messages:
            assessment = self.engine.analyze_message(message, [], {})
            
            # Should detect as low risk (< 0.75)
            assert assessment.risk_score < 0.75, f"Message should be low risk: {message} (score: {assessment.risk_score})"
    
    def test_ml_confidence_boost(self):
        """Test that ML predictions boost confidence when agreeing with rule-based."""
        message = "URGENT! Bank officer here. Send your UPI PIN immediately!"
        
        assessment = self.engine.analyze_message(message, [], {})
        
        # Should have high confidence due to ML and rule-based agreement
        assert assessment.confidence > 0.7
        
        # Should have both rule-based and ML risk factors
        rule_factors = [f for f in assessment.risk_factors if not f.startswith('ml_')]
        ml_factors = [f for f in assessment.risk_factors if f.startswith('ml_')]
        
        assert len(rule_factors) > 0
        assert len(ml_factors) > 0


class TestMLPerformanceAndAccuracy:
    """Test ML system performance and accuracy."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = MLScamDetector()
        self.detector.train_with_synthetic_data()
    
    def test_scam_detection_accuracy(self):
        """Test accuracy on known scam patterns."""
        scam_messages = [
            "URGENT! Your account will be blocked. Send OTP now.",
            "Congratulations! You won lottery. Share bank details.",
            "I am bank manager. Give me your PIN for verification.",
            "Emergency! Send money to 9876543210 immediately.",
            "Government scheme. Send Aadhar number to claim 50000."
        ]
        
        correct_predictions = 0
        for message in scam_messages:
            prediction = self.detector.predict(message)
            if prediction.probability > 0.5:  # Predicted as scam
                correct_predictions += 1
        
        accuracy = correct_predictions / len(scam_messages)
        assert accuracy >= 0.8, f"Scam detection accuracy too low: {accuracy}"
    
    def test_legitimate_message_accuracy(self):
        """Test accuracy on legitimate messages."""
        legitimate_messages = [
            "Hello, how are you doing today?",
            "The weather is really nice outside.",
            "Thank you for your help yesterday.",
            "Looking forward to meeting you soon.",
            "Have a great day ahead!"
        ]
        
        correct_predictions = 0
        for message in legitimate_messages:
            prediction = self.detector.predict(message)
            if prediction.probability <= 0.5:  # Predicted as legitimate
                correct_predictions += 1
        
        accuracy = correct_predictions / len(legitimate_messages)
        assert accuracy >= 0.8, f"Legitimate message accuracy too low: {accuracy}"
    
    def test_confidence_correlation(self):
        """Test that confidence correlates with prediction certainty."""
        test_messages = [
            ("URGENT SCAM ALERT SEND MONEY NOW!!!", True),  # Very obvious scam
            ("Hello friend, how are you?", False),  # Very obvious legitimate
        ]
        
        for message, is_scam in test_messages:
            prediction = self.detector.predict(message)
            
            # High certainty predictions should have high confidence
            if (is_scam and prediction.probability > 0.8) or (not is_scam and prediction.probability < 0.2):
                assert prediction.confidence > 0.6, f"Low confidence for certain prediction: {message}"
    
    def test_multilingual_support(self):
        """Test multilingual scam detection."""
        multilingual_scams = [
            "Paisa jaldi bhejo emergency hai",  # Hinglish
            "Trust karo main bank officer hun",  # Hinglish
            "Turant UPI ID share karo prize ke liye"  # Hinglish
        ]
        
        for message in multilingual_scams:
            prediction = self.detector.predict(message)
            # Should detect multilingual scams with reasonable accuracy
            assert prediction.probability > 0.3, f"Failed to detect multilingual scam: {message}"