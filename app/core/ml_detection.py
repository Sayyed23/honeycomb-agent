"""
ML-based scam classification system with text preprocessing, feature engineering,
and ensemble classification.
"""

import re
import string
import pickle
import joblib
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path
import logging
import numpy as np
import pandas as pd

# ML imports
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# NLTK imports
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    from nltk.stem import PorterStemmer
    from nltk.util import ngrams
    
    # Download required NLTK data
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    logging.warning("NLTK not available, using basic text processing")

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MLPrediction:
    """ML model prediction result."""
    probability: float
    confidence: float
    model_predictions: Dict[str, float]
    feature_importance: Dict[str, float]
    preprocessing_info: Dict[str, Any]


class TextPreprocessor:
    """
    Text preprocessing pipeline for feature extraction.
    Handles cleaning, normalization, and tokenization.
    """
    
    def __init__(self, language: str = 'en'):
        """
        Initialize text preprocessor.
        
        Args:
            language: Language code ('en', 'hi', 'hinglish')
        """
        self.language = language
        self.stemmer = PorterStemmer() if NLTK_AVAILABLE else None
        
        # Load stopwords based on language
        if NLTK_AVAILABLE:
            try:
                if language == 'hi':
                    # Hindi stopwords (basic set)
                    self.stopwords = set([
                        'और', 'का', 'के', 'की', 'को', 'से', 'में', 'पर', 'है', 'हैं',
                        'था', 'थे', 'थी', 'होगा', 'होगी', 'होंगे', 'यह', 'वह', 'इस',
                        'उस', 'कि', 'जो', 'तो', 'ही', 'भी', 'नहीं', 'न', 'कर', 'कुछ'
                    ])
                else:
                    self.stopwords = set(stopwords.words('english'))
            except:
                self.stopwords = set()
        else:
            # Basic English stopwords if NLTK not available
            self.stopwords = set([
                'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
                'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have',
                'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
                'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those'
            ])
        
        # Add common Hinglish stopwords
        if language in ['hinglish', 'hi']:
            hinglish_stopwords = {
                'hai', 'hain', 'kar', 'karo', 'kare', 'main', 'mein', 'aap', 'tum',
                'yeh', 'woh', 'koi', 'kuch', 'sab', 'sabhi', 'ek', 'do', 'teen',
                'char', 'paanch', 'se', 'tak', 'par', 'mein', 'pe', 'ka', 'ke', 'ki'
            }
            self.stopwords.update(hinglish_stopwords)
    
    def clean_text(self, text: str) -> str:
        """
        Clean and normalize text.
        
        Args:
            text: Raw text to clean
            
        Returns:
            str: Cleaned text
        """
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs
        text = re.sub(r'https?://\S+|www\.\S+', ' URL ', text)
        
        # Remove email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' EMAIL ', text)
        
        # Remove phone numbers (Indian format)
        text = re.sub(r'\b(?:\+91|91)?[6-9]\d{9}\b', ' PHONE ', text)
        
        # Remove UPI IDs
        text = re.sub(r'\b\w+@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)\b', ' UPI ', text)
        
        # Replace multiple punctuation with single space
        text = re.sub(r'[!]{2,}', ' EXCLAMATION ', text)
        text = re.sub(r'[?]{2,}', ' QUESTION ', text)
        
        # Remove extra punctuation but keep some for context
        text = re.sub(r'[^\w\s!?.,]', ' ', text)
        
        # Replace multiple whitespace with single space
        text = re.sub(r'\s+', ' ', text)
        
        # Remove leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def tokenize(self, text: str) -> List[str]:
        """
        Tokenize text into words.
        
        Args:
            text: Text to tokenize
            
        Returns:
            List[str]: List of tokens
        """
        if NLTK_AVAILABLE:
            try:
                tokens = word_tokenize(text)
            except:
                tokens = text.split()
        else:
            tokens = text.split()
        
        # Remove stopwords and short tokens
        tokens = [
            token for token in tokens 
            if len(token) > 2 and token.lower() not in self.stopwords
        ]
        
        return tokens
    
    def stem_tokens(self, tokens: List[str]) -> List[str]:
        """
        Apply stemming to tokens.
        
        Args:
            tokens: List of tokens to stem
            
        Returns:
            List[str]: Stemmed tokens
        """
        if not self.stemmer:
            return tokens
        
        try:
            return [self.stemmer.stem(token) for token in tokens]
        except:
            return tokens
    
    def preprocess(self, text: str) -> Dict[str, Any]:
        """
        Complete preprocessing pipeline.
        
        Args:
            text: Raw text to preprocess
            
        Returns:
            Dict[str, Any]: Preprocessing results
        """
        # Clean text
        cleaned_text = self.clean_text(text)
        
        # Tokenize
        tokens = self.tokenize(cleaned_text)
        
        # Stem tokens
        stemmed_tokens = self.stem_tokens(tokens)
        
        # Rejoin tokens
        processed_text = ' '.join(stemmed_tokens)
        
        return {
            'original_text': text,
            'cleaned_text': cleaned_text,
            'tokens': tokens,
            'stemmed_tokens': stemmed_tokens,
            'processed_text': processed_text,
            'token_count': len(tokens),
            'char_count': len(cleaned_text)
        }


class FeatureEngineer:
    """
    Feature engineering for scam detection using TF-IDF, n-grams, and custom features.
    """
    
    def __init__(self, max_features: int = 5000):
        """
        Initialize feature engineer.
        
        Args:
            max_features: Maximum number of features to extract
        """
        self.max_features = max_features
        
        # TF-IDF vectorizers
        self.tfidf_word = TfidfVectorizer(
            max_features=max_features // 2,
            ngram_range=(1, 2),  # Unigrams and bigrams
            min_df=1,  # Reduced from 2 to handle small datasets
            max_df=0.95,
            stop_words=None  # We handle stopwords in preprocessing
        )
        
        self.tfidf_char = TfidfVectorizer(
            max_features=max_features // 4,
            analyzer='char',
            ngram_range=(2, 4),  # Character n-grams
            min_df=1,  # Reduced from 2 to handle small datasets
            max_df=0.95
        )
        
        # Count vectorizer for n-grams
        self.count_vectorizer = CountVectorizer(
            max_features=max_features // 4,
            ngram_range=(1, 3),  # Unigrams, bigrams, trigrams
            min_df=1,  # Reduced from 2 to handle small datasets
            max_df=0.95
        )
        
        self.is_fitted = False
    
    def extract_custom_features(self, text: str) -> Dict[str, float]:
        """
        Extract custom features from text.
        
        Args:
            text: Text to extract features from
            
        Returns:
            Dict[str, float]: Custom features
        """
        features = {}
        
        if not text:
            return {f'custom_{i}': 0.0 for i in range(20)}
        
        text_lower = text.lower()
        
        # Length features
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['avg_word_length'] = np.mean([len(word) for word in text.split()]) if text.split() else 0
        
        # Punctuation features
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediately', 'asap', 'emergency', 'quick', 'fast', 'hurry']
        features['urgency_score'] = sum(1 for word in urgency_words if word in text_lower)
        
        # Financial keywords
        financial_words = ['money', 'payment', 'bank', 'account', 'upi', 'transfer', 'cash']
        features['financial_score'] = sum(1 for word in financial_words if word in text_lower)
        
        # Social engineering indicators
        trust_words = ['trust', 'honest', 'genuine', 'official', 'authorized', 'verified']
        features['trust_score'] = sum(1 for word in trust_words if word in text_lower)
        
        # Authority claims
        authority_words = ['officer', 'manager', 'executive', 'representative', 'agent']
        features['authority_score'] = sum(1 for word in authority_words if word in text_lower)
        
        # Fear tactics
        fear_words = ['blocked', 'suspended', 'cancelled', 'penalty', 'fine', 'legal']
        features['fear_score'] = sum(1 for word in fear_words if word in text_lower)
        
        # Contact requests
        contact_patterns = [
            r'(?:send|share|give|provide).*(?:number|phone|mobile)',
            r'(?:your|apka).*(?:number|phone|mobile)',
            r'(?:bank|account).*(?:details|number)'
        ]
        features['contact_request_score'] = sum(
            1 for pattern in contact_patterns if re.search(pattern, text_lower)
        )
        
        # Suspicious patterns
        features['phone_number_present'] = 1.0 if re.search(r'\b(?:\+91|91)?[6-9]\d{9}\b', text) else 0.0
        features['upi_id_present'] = 1.0 if re.search(r'\b\w+@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)\b', text_lower) else 0.0
        features['url_present'] = 1.0 if re.search(r'https?://\S+', text) else 0.0
        features['email_present'] = 1.0 if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text) else 0.0
        
        # Repetition features
        features['repeated_chars'] = len(re.findall(r'(.)\1{2,}', text))
        features['repeated_words'] = len(text.split()) - len(set(text.split())) if text.split() else 0
        
        # Language mixing (for Hinglish detection)
        hinglish_words = ['kya', 'hai', 'kar', 'main', 'aap', 'yeh', 'paisa', 'bhejo']
        features['hinglish_score'] = sum(1 for word in hinglish_words if word in text_lower)
        
        # Normalize features to [0, 1] range where appropriate
        max_length = 1000  # Assume max reasonable message length
        features['text_length'] = min(features['text_length'] / max_length, 1.0)
        features['word_count'] = min(features['word_count'] / 100, 1.0)  # Max 100 words
        features['avg_word_length'] = min(features['avg_word_length'] / 15, 1.0)  # Max 15 chars per word
        
        return features
    
    def fit(self, texts: List[str]) -> 'FeatureEngineer':
        """
        Fit feature extractors on training data.
        
        Args:
            texts: List of training texts
            
        Returns:
            FeatureEngineer: Self for chaining
        """
        logger.info(f"Fitting feature extractors on {len(texts)} texts")
        
        # Fit TF-IDF vectorizers
        self.tfidf_word.fit(texts)
        self.tfidf_char.fit(texts)
        self.count_vectorizer.fit(texts)
        
        self.is_fitted = True
        logger.info("Feature extractors fitted successfully")
        
        return self
    
    def transform(self, texts: List[str]) -> np.ndarray:
        """
        Transform texts to feature vectors.
        
        Args:
            texts: List of texts to transform
            
        Returns:
            np.ndarray: Feature matrix
        """
        if not self.is_fitted:
            raise ValueError("FeatureEngineer must be fitted before transform")
        
        # Extract TF-IDF features
        tfidf_word_features = self.tfidf_word.transform(texts).toarray()
        tfidf_char_features = self.tfidf_char.transform(texts).toarray()
        count_features = self.count_vectorizer.transform(texts).toarray()
        
        # Extract custom features
        custom_features = []
        for text in texts:
            custom_feat = self.extract_custom_features(text)
            custom_features.append(list(custom_feat.values()))
        
        custom_features = np.array(custom_features)
        
        # Combine all features
        all_features = np.hstack([
            tfidf_word_features,
            tfidf_char_features,
            count_features,
            custom_features
        ])
        
        logger.debug(f"Transformed {len(texts)} texts to {all_features.shape[1]} features")
        
        return all_features
    
    def fit_transform(self, texts: List[str]) -> np.ndarray:
        """
        Fit and transform texts in one step.
        
        Args:
            texts: List of texts to fit and transform
            
        Returns:
            np.ndarray: Feature matrix
        """
        return self.fit(texts).transform(texts)
    
    def get_feature_names(self) -> List[str]:
        """
        Get names of all features.
        
        Returns:
            List[str]: Feature names
        """
        if not self.is_fitted:
            return []
        
        feature_names = []
        
        # TF-IDF word features
        feature_names.extend([f"tfidf_word_{name}" for name in self.tfidf_word.get_feature_names_out()])
        
        # TF-IDF char features
        feature_names.extend([f"tfidf_char_{name}" for name in self.tfidf_char.get_feature_names_out()])
        
        # Count features
        feature_names.extend([f"count_{name}" for name in self.count_vectorizer.get_feature_names_out()])
        
        # Custom features
        custom_feature_names = [
            'text_length', 'word_count', 'avg_word_length', 'exclamation_count',
            'question_count', 'caps_ratio', 'urgency_score', 'financial_score',
            'trust_score', 'authority_score', 'fear_score', 'contact_request_score',
            'phone_number_present', 'upi_id_present', 'url_present', 'email_present',
            'repeated_chars', 'repeated_words', 'hinglish_score'
        ]
        feature_names.extend(custom_feature_names)
        
        return feature_names


class EnsembleScamClassifier:
    """
    Ensemble classifier combining multiple ML models for scam detection.
    """
    
    def __init__(self, random_state: int = 42):
        """
        Initialize ensemble classifier.
        
        Args:
            random_state: Random state for reproducibility
        """
        self.random_state = random_state
        
        # Individual models
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=random_state,
                class_weight='balanced'
            ),
            'svm': SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                probability=True,
                random_state=random_state,
                class_weight='balanced'
            ),
            'naive_bayes': MultinomialNB(alpha=1.0),
            'logistic_regression': LogisticRegression(
                C=1.0,
                max_iter=1000,
                random_state=random_state,
                class_weight='balanced'
            )
        }
        
        # Ensemble model
        self.ensemble = VotingClassifier(
            estimators=list(self.models.items()),
            voting='soft'  # Use probability averaging
        )
        
        self.is_fitted = False
        self.feature_importance_ = None
    
    def fit(self, X: np.ndarray, y: np.ndarray) -> 'EnsembleScamClassifier':
        """
        Fit the ensemble classifier.
        
        Args:
            X: Feature matrix
            y: Target labels
            
        Returns:
            EnsembleScamClassifier: Self for chaining
        """
        logger.info(f"Training ensemble classifier on {X.shape[0]} samples with {X.shape[1]} features")
        
        # Fit individual models
        for name, model in self.models.items():
            logger.info(f"Training {name}")
            model.fit(X, y)
        
        # Fit ensemble
        logger.info("Training ensemble")
        self.ensemble.fit(X, y)
        
        # Calculate feature importance (from Random Forest)
        if hasattr(self.models['random_forest'], 'feature_importances_'):
            self.feature_importance_ = self.models['random_forest'].feature_importances_
        
        self.is_fitted = True
        logger.info("Ensemble classifier training completed")
        
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict class probabilities.
        
        Args:
            X: Feature matrix
            
        Returns:
            np.ndarray: Probability predictions
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted before prediction")
        
        return self.ensemble.predict_proba(X)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict class labels.
        
        Args:
            X: Feature matrix
            
        Returns:
            np.ndarray: Class predictions
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted before prediction")
        
        return self.ensemble.predict(X)
    
    def get_individual_predictions(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Get predictions from individual models.
        
        Args:
            X: Feature matrix
            
        Returns:
            Dict[str, np.ndarray]: Individual model predictions
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted before prediction")
        
        predictions = {}
        for name, model in self.models.items():
            predictions[name] = model.predict_proba(X)[:, 1]  # Probability of positive class
        
        return predictions
    
    def calculate_confidence(self, probabilities: np.ndarray) -> np.ndarray:
        """
        Calculate prediction confidence based on probability distribution.
        
        Args:
            probabilities: Probability predictions
            
        Returns:
            np.ndarray: Confidence scores
        """
        # Confidence based on distance from 0.5 (uncertainty)
        max_probs = np.max(probabilities, axis=1)
        confidence = 2 * np.abs(max_probs - 0.5)  # Scale to [0, 1]
        
        return confidence
    
    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model performance.
        
        Args:
            X: Feature matrix
            y: True labels
            
        Returns:
            Dict[str, Any]: Evaluation metrics
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted before evaluation")
        
        # Predictions
        y_pred = self.predict(X)
        y_proba = self.predict_proba(X)
        
        # Metrics
        accuracy = accuracy_score(y, y_pred)
        
        # Cross-validation scores
        cv_scores = cross_val_score(self.ensemble, X, y, cv=3, scoring='accuracy')  # Reduced from 5 to 3
        
        return {
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': classification_report(y, y_pred, output_dict=True),
            'confusion_matrix': confusion_matrix(y, y_pred).tolist()
        }


class MLScamDetector:
    """
    Complete ML-based scam detection system combining preprocessing,
    feature engineering, and ensemble classification.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize ML scam detector.
        
        Args:
            model_path: Path to saved model files
        """
        self.model_path = Path(model_path) if model_path else Path("models")
        self.model_path.mkdir(exist_ok=True)
        
        self.preprocessor = TextPreprocessor()
        self.feature_engineer = FeatureEngineer()
        self.classifier = EnsembleScamClassifier()
        
        self.is_trained = False
        
        # Try to load existing model
        self._load_model()
    
    def train(self, texts: List[str], labels: List[int]) -> Dict[str, Any]:
        """
        Train the ML scam detector.
        
        Args:
            texts: Training texts
            labels: Training labels (0 = legitimate, 1 = scam)
            
        Returns:
            Dict[str, Any]: Training results
        """
        logger.info(f"Training ML scam detector on {len(texts)} samples")
        
        # Preprocess texts
        processed_texts = []
        for text in texts:
            processed = self.preprocessor.preprocess(text)
            processed_texts.append(processed['processed_text'])
        
        # Extract features
        X = self.feature_engineer.fit_transform(processed_texts)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train classifier
        self.classifier.fit(X_train, y_train)
        
        # Evaluate
        train_metrics = self.classifier.evaluate(X_train, y_train)
        test_metrics = self.classifier.evaluate(X_test, y_test)
        
        self.is_trained = True
        
        # Save model
        self._save_model()
        
        results = {
            'train_metrics': train_metrics,
            'test_metrics': test_metrics,
            'feature_count': X.shape[1],
            'training_samples': len(texts)
        }
        
        logger.info(f"Training completed. Test accuracy: {test_metrics['accuracy']:.3f}")
        
        return results
    
    def predict(self, text: str, conversation_history: List[str] = None) -> MLPrediction:
        """
        Predict if text is a scam.
        
        Args:
            text: Text to analyze
            conversation_history: Previous conversation messages
            
        Returns:
            MLPrediction: Prediction result
        """
        if not self.is_trained:
            # Return default prediction if not trained
            return MLPrediction(
                probability=0.1,
                confidence=0.3,
                model_predictions={},
                feature_importance={},
                preprocessing_info={}
            )
        
        # Preprocess text
        preprocessing_info = self.preprocessor.preprocess(text)
        processed_text = preprocessing_info['processed_text']
        
        # Add conversation context if available
        if conversation_history:
            context_text = ' '.join(conversation_history[-3:])  # Last 3 messages
            processed_text = f"{processed_text} CONTEXT: {context_text}"
        
        # Extract features
        X = self.feature_engineer.transform([processed_text])
        
        # Get predictions
        probabilities = self.classifier.predict_proba(X)
        scam_probability = probabilities[0, 1]  # Probability of scam class
        
        # Calculate confidence
        confidence = self.classifier.calculate_confidence(probabilities)[0]
        
        # Get individual model predictions
        individual_predictions = self.classifier.get_individual_predictions(X)
        model_predictions = {name: float(pred[0]) for name, pred in individual_predictions.items()}
        
        # Get feature importance
        feature_names = self.feature_engineer.get_feature_names()
        if self.classifier.feature_importance_ is not None and len(feature_names) == len(self.classifier.feature_importance_):
            # Get top 10 most important features for this prediction
            feature_values = X[0]
            importance_scores = self.classifier.feature_importance_ * np.abs(feature_values)
            top_indices = np.argsort(importance_scores)[-10:]
            
            feature_importance = {
                feature_names[i]: float(importance_scores[i])
                for i in top_indices
                if importance_scores[i] > 0
            }
        else:
            feature_importance = {}
        
        return MLPrediction(
            probability=float(scam_probability),
            confidence=float(confidence),
            model_predictions=model_predictions,
            feature_importance=feature_importance,
            preprocessing_info=preprocessing_info
        )
    
    def _save_model(self):
        """Save trained model to disk."""
        try:
            # Save feature engineer
            joblib.dump(self.feature_engineer, self.model_path / "feature_engineer.pkl")
            
            # Save classifier
            joblib.dump(self.classifier, self.model_path / "classifier.pkl")
            
            # Save metadata
            metadata = {
                'is_trained': self.is_trained,
                'model_version': '1.0',
                'feature_count': len(self.feature_engineer.get_feature_names()) if self.feature_engineer.is_fitted else 0
            }
            
            with open(self.model_path / "metadata.json", 'w') as f:
                import json
                json.dump(metadata, f)
            
            logger.info(f"Model saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def _load_model(self):
        """Load trained model from disk."""
        try:
            feature_engineer_path = self.model_path / "feature_engineer.pkl"
            classifier_path = self.model_path / "classifier.pkl"
            metadata_path = self.model_path / "metadata.json"
            
            if all(path.exists() for path in [feature_engineer_path, classifier_path, metadata_path]):
                # Load components
                self.feature_engineer = joblib.load(feature_engineer_path)
                self.classifier = joblib.load(classifier_path)
                
                # Load metadata
                with open(metadata_path, 'r') as f:
                    import json
                    metadata = json.load(f)
                
                self.is_trained = metadata.get('is_trained', False)
                
                logger.info(f"Model loaded from {self.model_path}")
            else:
                logger.info("No existing model found, will need to train")
                
        except Exception as e:
            logger.warning(f"Error loading model: {e}")
            self.is_trained = False
    
    def create_training_data(self) -> Tuple[List[str], List[int]]:
        """
        Create synthetic training data for initial model training.
        This is a placeholder - in production, you would use real labeled data.
        
        Returns:
            Tuple[List[str], List[int]]: (texts, labels)
        """
        # Scam examples (label = 1) - Expanded dataset
        scam_texts = [
            "URGENT! Your bank account will be blocked. Send OTP immediately to verify.",
            "Congratulations! You won 50,000 rupees. Share your UPI ID to claim prize.",
            "I am bank manager. Your account has suspicious activity. Give me your PIN.",
            "Emergency! Send money to this account: 1234567890. Trust me, I am officer.",
            "Limited time offer! Invest 10,000 and get 50,000 return. Call 9876543210.",
            "Your card is blocked. Immediately share CVV and expiry date to unblock.",
            "Government scheme: Get 25,000 cash. Send Aadhar number and bank details.",
            "Urgent payment required. Transfer money to paytm@123 within 1 hour.",
            "I am from customer care. Your account will be closed. Share password now.",
            "Lucky winner! You got lottery of 1 lakh. Send 5000 processing fee first.",
            "Bank verification needed. What is your account number and IFSC code?",
            "Emergency fund transfer. Send money to 9876543210 immediately. Trust me.",
            "Your UPI is compromised. Share OTP received to secure your account.",
            "Exclusive offer! Double your money in 24 hours. Invest now or lose chance.",
            "Police case against you. Pay fine 10,000 to avoid arrest. Call urgently.",
            "Paisa jaldi bhejo emergency hai. Trust karo main officer hun.",
            "Turant UPI ID share karo prize claim karne ke liye.",
            "Bank se call kar raha hun. Account block hone wala hai. OTP do.",
            "Government yojana hai. 50,000 milega. Bank details bhejo abhi.",
            "Investment opportunity hai. 1 lakh invest karo, 5 lakh milega.",
            "URGENT ALERT! Your account shows suspicious activity. Verify immediately.",
            "Congratulations! You are selected for cash prize. Send bank details now.",
            "I am calling from RBI. Your account needs immediate verification.",
            "LAST CHANCE! Claim your reward before it expires. Send UPI ID.",
            "Your debit card will expire today. Update details to avoid blocking.",
            "Emergency! Family member in hospital. Send money urgently to save life.",
            "Tax refund of 25000 approved. Share bank account to receive money.",
            "Your mobile number won lottery. Pay processing fee to claim prize.",
            "Account security alert! Verify PIN and CVV to prevent fraud.",
            "Government relief fund available. Send documents to claim 50000.",
            "URGENT! Cyber crime reported on your account. Share OTP to secure.",
            "Bank merger happening. Transfer money to new account immediately.",
            "Your KYC is expired. Update now or account will be frozen.",
            "Lucky draw winner! You won iPhone. Pay delivery charges to receive.",
            "Insurance claim approved. Share bank details to receive payment.",
            "Credit card pre-approved. Send salary slip and bank statement.",
            "ATM card blocked due to wrong PIN. Share correct PIN to unblock.",
            "Online shopping refund pending. Confirm bank details to process.",
            "Electricity bill payment failed. Pay penalty to avoid disconnection.",
            "Income tax notice. Pay fine immediately to avoid legal action.",
            "Jaldi karo! Paisa bhejne ka last chance hai. Trust me officer hun.",
            "Emergency mein hun. Turant 10000 bhejo. Main wapas kar dunga.",
            "Bank wale call kar rahe hain. OTP share karo account safe karne ke liye.",
            "Lottery jeet gaye ho. Processing fee bhejo prize claim karne ke liye.",
            "Government scheme hai. Documents bhejo 25000 claim karne ke liye."
        ]
        
        # Legitimate examples (label = 0) - Expanded dataset
        legitimate_texts = [
            "Hello, how are you doing today? Hope you are well.",
            "Thank you for your help yesterday. I really appreciate it.",
            "The weather is really nice today. Perfect for a walk.",
            "I enjoyed our conversation. Looking forward to meeting again.",
            "Have a great day ahead! Take care of yourself.",
            "How was your weekend? Did you do anything interesting?",
            "I am running a bit late. Will reach in 15 minutes.",
            "The movie was really good. You should watch it sometime.",
            "Happy birthday! Hope you have a wonderful celebration.",
            "Good morning! Ready for another productive day?",
            "The food at that restaurant was delicious. Highly recommend.",
            "Traffic is heavy today. Better to leave early.",
            "Congratulations on your new job! Well deserved success.",
            "The book you recommended was fascinating. Thank you.",
            "Let's plan a trip sometime. It will be fun.",
            "Kya haal hai? Sab theek? Long time no see.",
            "Aaj weather kaafi accha hai. Bahar jaane ka mann kar raha.",
            "Thanks yaar for helping me yesterday. Really appreciate.",
            "Movie dekhi? Kaisi lagi? I heard it's really good.",
            "Weekend plans kya hain? Kuch special kar rahe ho?",
            "Office mein kaam kaisa chal raha hai? All good?",
            "Family sab theek hai na? Long time since we talked.",
            "Vacation plans bana rahe hain. Kahan jaana hai?",
            "New restaurant try kiya? Food kaisa tha?",
            "Exercise kar rahe ho요즘? Health maintain karna important hai.",
            "Good morning! Hope you slept well last night.",
            "The presentation went really well today. Thanks for your support.",
            "Looking forward to the weekend. Any plans?",
            "The new coffee shop near office is quite good.",
            "How is your family doing? Send my regards to everyone.",
            "The project deadline is next week. We should meet to discuss.",
            "I found a great deal on flights. Want to check it out?",
            "The concert last night was amazing. You missed a great show.",
            "Can we reschedule our meeting to tomorrow? Something came up.",
            "The weather forecast says it might rain. Carry an umbrella.",
            "I finished reading that book you suggested. Loved it!",
            "The new season of our favorite show is out. Shall we binge watch?",
            "My cooking experiment failed today. Ordering food instead.",
            "The gym was crowded today. Had to wait for equipment.",
            "I'm thinking of learning a new language. Any suggestions?",
            "The garden is looking beautiful with all the flowers blooming.",
            "I need to buy groceries. Want to come along?",
            "The traffic was terrible this morning. Took an hour to reach.",
            "I'm planning to redecorate my room. Any color suggestions?",
            "The new employee seems nice. Hope they settle in well."
        ]
        
        # Combine texts and labels
        texts = scam_texts + legitimate_texts
        labels = [1] * len(scam_texts) + [0] * len(legitimate_texts)
        
        # Shuffle data
        from random import shuffle
        combined = list(zip(texts, labels))
        shuffle(combined)
        texts, labels = zip(*combined)
        
        return list(texts), list(labels)
    
    def train_with_synthetic_data(self) -> Dict[str, Any]:
        """
        Train the model with synthetic data.
        This is for initial setup - replace with real data in production.
        
        Returns:
            Dict[str, Any]: Training results
        """
        logger.info("Training with synthetic data")
        
        texts, labels = self.create_training_data()
        return self.train(texts, labels)