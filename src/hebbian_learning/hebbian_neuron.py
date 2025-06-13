# hebbian_learning/hebbian_neuron.py

import numpy as np
import logging

logger = logging.getLogger(__name__)

class HebbianNeuron:
    """
    Implémentation d'un neurone Hebbien simple.
    Les poids du neurone s'ajustent en fonction de la corrélation entre
    ses entrées et son activité, modulée par un signal de feedback.
    """
    def __init__(self, num_inputs: int, learning_rate: float = 0.01, decay_rate: float = 0.001):
        """
        Initialise un neurone Hebbien.

        Args:
            num_inputs (int): Le nombre d'entrées que le neurone attend.
            learning_rate (float): Le taux d'apprentissage pour l'ajustement des poids.
            decay_rate (float): Le taux de déclin appliqué aux poids pour favoriser l'oubli.
        """
        self.weights = np.random.rand(num_inputs) * 0.1 # Initialize small random weights
        self.learning_rate = learning_rate
        self.decay_rate = decay_rate
        self.activation = 0.0
        logger.debug(f"HebbianNeuron initialized with {num_inputs} inputs.")

    def activate(self, inputs: np.ndarray) -> float:
        """
        Calcule l'activation du neurone comme le produit scalaire des entrées et des poids.

        Args:
            inputs (np.ndarray): Un tableau NumPy des valeurs d'entrée.

        Returns:
            float: La valeur d'activation du neurone.
        """
        if not isinstance(inputs, np.ndarray):
            inputs = np.array(inputs)
        if inputs.shape != self.weights.shape:
            raise ValueError(f"Input shape {inputs.shape} does not match weights shape {self.weights.shape}")

        self.activation = np.dot(inputs, self.weights)
        logger.debug(f"Neuron activation: {self.activation:.4f}")
        return self.activation

    def update_weights(self, inputs: np.ndarray, output: float, feedback_signal: int):
        """
        Met à jour les poids du neurone selon la règle de Hebb, modulée par un signal de feedback.

        Args:
            inputs (np.ndarray): Les entrées qui ont conduit à l'activation.
            output (float): L'activation du neurone pour ces entrées.
            feedback_signal (int): Signal de feedback (+1 pour succès, -1 pour échec, 0 pour neutre).
        """
        if not isinstance(inputs, np.ndarray):
            inputs = np.array(inputs)

        # Apply Hebbian learning: weights increase if inputs and output are correlated, modulated by feedback
        delta_weights = self.learning_rate * feedback_signal * inputs * output
        self.weights += delta_weights
        
        # Apply decay to prevent weights from growing indefinitely and encourage forgetting less useful patterns
        self.weights *= (1 - self.decay_rate)
        
        # Keep weights normalized or bounded if necessary for stability
        self.weights = np.clip(self.weights, -1.0, 1.0) # Example clipping
        logger.debug(f"Weights updated. First few weights: {self.weights[:5]}")

# Example Usage (for testing)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Create a neuron with 5 inputs
    neuron = HebbianNeuron(num_inputs=5)
    print(f"Initial weights: {neuron.weights}")

    # Simulate inputs and feedback
    inputs1 = np.array([0.1, 0.5, 0.2, 0.8, 0.3])
    output1 = neuron.activate(inputs1)
    print(f"Activation for inputs1: {output1}")
    neuron.update_weights(inputs1, output1, 1) # Positive feedback
    print(f"Weights after positive feedback: {neuron.weights}")

    inputs2 = np.array([0.9, 0.1, 0.7, 0.2, 0.5])
    output2 = neuron.activate(inputs2)
    print(f"Activation for inputs2: {output2}")
    neuron.update_weights(inputs2, output2, -1) # Negative feedback
    print(f"Weights after negative feedback: {neuron.weights}")

    inputs3 = np.array([0.1, 0.5, 0.2, 0.8, 0.3]) # Same as inputs1
    output3 = neuron.activate(inputs3)
    print(f"Activation for inputs3: {output3}")
    # After positive feedback on similar inputs, activation should be higher or weights adjusted to favor it
    neuron.update_weights(inputs3, output3, 1)
    print(f"Weights after another positive feedback (same inputs): {neuron.weights}")
