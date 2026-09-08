from abc import ABC, abstractmethod

class BaseDetector(ABC):
    """
    Abstract interface for all threat detectors in Phase 4.
    """
    
    @abstractmethod
    def predict(self, feature_vector):
        """
        Consumes a feature vector dictionary and returns a prediction tuple.
        
        Args:
            feature_vector (dict): The output from a Phase 3 feature extractor module.
            
        Returns:
            tuple: (score, feature_values, explanation_string)
                - score (float): The anomaly/threat score or probability (0.0 to 1.0).
                - feature_values (dict): The subset of features used for the prediction.
                - explanation_string (str): Human-readable context, e.g., "SYN-ratio 9.2x baseline". 
                                            Must not be empty for true positives.
        """
        pass

    def predict_batch(self, feature_vectors: list):
        """
        Consumes a list of feature vector dictionaries and returns a list of prediction tuples.
        Useful for bulk evaluation to avoid loop overhead. Base implementation just loops.
        """
        results = []
        for fv in feature_vectors:
            results.append(self.predict(fv))
        return results
