import os
import warnings
import logging
import json
from flask import Flask, request, render_template, jsonify, abort
from werkzeug.utils import secure_filename
import base64

# Suppress TensorFlow logs and warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
warnings.filterwarnings('ignore')
logging.getLogger('tensorflow').setLevel(logging.ERROR)

from keras.models import load_model
from PIL import Image, ImageOps
import numpy as np
import tensorflow as tf

# Disable scientific notation for clarity
np.set_printoptions(suppress=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Custom function to handle the deprecated 'groups' parameter
def custom_depthwise_conv2d(*args, **kwargs):
    kwargs.pop('groups', None)
    return tf.keras.layers.DepthwiseConv2D(*args, **kwargs)

# Global variables for model, labels and condition details
model = None
class_names = None
condition_details = None

def load_condition_details():
    """Load the condition details from JSON file"""
    global condition_details
    try:
        with open("details.json", "r") as f:
            data = json.load(f)
            condition_details = {condition['name']: condition for condition in data['skin_conditions']}
        print("Condition details loaded successfully!")
        return True
    except FileNotFoundError:
        print("Error: details.json file not found!")
        return False
    except Exception as e:
        print(f"Error loading condition details: {e}")
        return False

def load_ml_model():
    """Load the machine learning model and labels"""
    global model, class_names
    
    custom_objects = {'DepthwiseConv2D': custom_depthwise_conv2d}
    
    try:
        model = load_model(r"Rash_Models\Rash_model.h5", compile=False, custom_objects=custom_objects)
        print("Model loaded successfully!")
    except Exception as e:
        print(f"Error loading model: {e}")
        return False
    
    try:
        class_names = open("Rash_Models/labels.txt", "r").readlines()
        print("Labels loaded successfully!")
    except FileNotFoundError:
        print("Error: labels.txt file not found!")
        return False
    
    return True

def get_condition_info(class_name):
    """Get detailed information about the detected condition"""
    if condition_details is None:
        return None
    
    # Clean the class name and try to find a match
    clean_name = class_name.strip()
    
    # Try exact match first
    if clean_name in condition_details:
        return condition_details[clean_name]
    
    # Try partial matching for common variations
    for condition_key in condition_details.keys():
        if clean_name.lower() in condition_key.lower() or condition_key.lower() in clean_name.lower():
            return condition_details[condition_key]
    
    return None

def predict_image(image_path):
    """Predict the class of an uploaded image and return all confidences"""
    try:
        # Open and convert image
        image = Image.open(image_path).convert("RGB")
        
        # Resize and crop image
        size = (224, 224)
        image = ImageOps.fit(image, size, Image.Resampling.LANCZOS)
        
        # Convert to numpy array
        image_array = np.asarray(image)
        
        # Normalize the image
        normalized_image_array = (image_array.astype(np.float32) / 127.5) - 1
        
        # Create data array
        data = np.ndarray(shape=(1, 224, 224, 3), dtype=np.float32)
        data[0] = normalized_image_array
        
        # Make prediction
        prediction = model.predict(data)
        index = np.argmax(prediction)
        top_class_name = class_names[index]
        top_confidence_score = prediction[0][index]
        
        # Get all class confidences
        all_confidences = []
        for i, confidence in enumerate(prediction[0]):
            class_name_clean = class_names[i][2:].strip() if class_names[i].startswith(('0 ', '1 ')) else class_names[i].strip()
            all_confidences.append({
                'class': class_name_clean,
                'confidence': float(confidence),
                'percentage': float(confidence * 100)
            })
        
        # Sort by confidence (highest to lowest)
        all_confidences.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Clean top class name
        clean_top_class_name = top_class_name[2:].strip() if top_class_name.startswith(('0 ', '1 ')) else top_class_name.strip()
        
        # Check if confidence is less than 30%
        if top_confidence_score < 0.30:
            return {
                'top_prediction': {
                    'class': 'Unknown',
                    'confidence': float(top_confidence_score),
                    'details': {
                        'name': 'Unknown Condition',
                        'causes': ['Insufficient confidence in prediction to determine specific condition'],
                        'potential_harms': ['Please consult a healthcare professional for proper diagnosis'],
                        'possible_progression': ['Medical evaluation recommended for accurate assessment']
                    }
                },
                'all_confidences': all_confidences
            }
        
        # Get detailed condition information
        condition_info = get_condition_info(clean_top_class_name)
        
        result = {
            'top_prediction': {
                'class': clean_top_class_name,
                'confidence': float(top_confidence_score)
            },
            'all_confidences': all_confidences
        }
        
        if condition_info:
            result['top_prediction']['details'] = condition_info
        
        return result
    
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    if file and allowed_file(file.filename):
        try:
            # Save uploaded file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Make prediction
            result = predict_image(filepath)
            
            # Convert image to base64 for display
            with open(filepath, "rb") as img_file:
                img_base64 = base64.b64encode(img_file.read()).decode('utf-8')
            
            
            # Clean up uploaded file
            os.remove(filepath)
            
            if 'error' in result:
                return jsonify({'error': result['error']})
            
            # Load classification details
            try:
                with open('details.json', 'r') as file:
                    data = json.load(file)

                predicted_class = result['top_prediction']['class']
                
                # Find matching classification - more robust matching
                classification_info = None
                for condition in data['skin_conditions']:
                    if condition['name'].lower() == predicted_class.lower():
                        classification_info = {
                            "classification": condition.get("classification", "Unknown"),
                            "name": condition['name']
                        }
                        break
                
                # If no exact match found, use default
                if not classification_info:
                    classification_info = {
                        "classification": "Unknown", 
                        "name": predicted_class
                    }
                    
            except Exception as e:
                print(f"Error loading classification: {e}")
                classification_info = {
                    "classification": "Unknown", 
                    "name": result['top_prediction']['class']
                }
            
            response_data = {
                'success': True,
                'top_prediction': result['top_prediction'],
                'all_confidences': result['all_confidences'],
                'image': img_base64,
                'classification': classification_info
            }
            
            return jsonify(response_data)
        except Exception as e:
            return jsonify({'error': f'Error processing image: {str(e)}'})
    
    return jsonify({'error': 'Invalid file type. Please upload an image file.'})


@app.route('/api/random-images/<path:image_path>')
def get_random_images(image_path):
    import os
    import random
    
    try:
        # Construct the full path to the image directory
        full_path = os.path.join(image_path)
        
        print(f"Looking for images in: {full_path}")  # Debug print
        
        if os.path.exists(full_path) and os.path.isdir(full_path):
            all_images = [f for f in os.listdir(full_path) 
                         if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'))]
            
            print(f"Found {len(all_images)} images: {all_images[:5]}")  # Debug print
            
            if not all_images:
                return jsonify({'images': [], 'message': 'No images found in directory'})
            
            # Get 3-5 random images
            num_images = min(random.randint(3, 5), len(all_images))
            selected_images = random.sample(all_images, num_images)
            
            # Create proper URLs - Flask will serve static files from the static folder
            image_urls = []
            for img in selected_images:
                # Convert the path to web-accessible URL
                if image_path.startswith('static/'):
                    # Remove 'static/' prefix since Flask serves it automatically
                    web_path = image_path[7:] + '/' + img
                else:
                    web_path = image_path + '/' + img
                
                image_urls.append(f"/static/{web_path}")
            
            print(f"Generated URLs: {image_urls}")  # Debug print
            
            return jsonify({'images': image_urls})
        else:
            print(f"Directory does not exist: {full_path}")  # Debug print
            return jsonify({'images': [], 'error': f'Directory not found: {full_path}'})
            
    except Exception as e:
        print(f"Error in get_random_images: {str(e)}")  # Debug print
        return jsonify({'error': str(e), 'images': []})

# Alternative route if you need to serve dataset files directly
@app.route('/dataset/<path:filename>')
def serve_dataset_file(filename):
    """Serve files from the dataset directory"""
    try:
        return send_from_directory('static/dataset', filename)
    except Exception as e:
        print(f"Error serving dataset file: {str(e)}")
        abort(404)

@app.route('/disease/<string:disease_name>')
def disease(disease_name):
    # Read the JSON data from details.json
    try:
        with open('details.json', 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print("details.json file not found")
        abort(404)
    except json.JSONDecodeError:
        print("Error parsing details.json")
        abort(500)
        
    # Find the specific disease
    selected_disease = None
    for condition in data['skin_conditions']:
        # Create URL-friendly version of the condition name for comparison
        condition_url_name = condition['name'].lower().replace(' ', '-').replace('_', '-')
        # Remove special characters
        condition_url_name = ''.join(c for c in condition_url_name if c.isalnum() or c == '-')
        
        if condition_url_name == disease_name.lower():
            selected_disease = condition
            break
    
    if selected_disease is None:
        print(f"Disease not found: {disease_name}")
        abort(404)
    
    # Debug print to check image path
    print(f"Selected disease: {selected_disease['name']}")
    print(f"Image path: {selected_disease.get('image_path', 'No image path')}")
    
    # Pass both the selected disease and all conditions for the dropdown
    return render_template('details.html', 
                         disease=selected_disease, 
                         all_conditions=data['skin_conditions'])

                         
@app.route('/disease-details')
def home():
    # Read the JSON data to get all disease names for the home page
    with open('details.json', 'r') as file:
        data = json.load(file)
    
    return render_template('disease_database.html', skin_conditions=data['skin_conditions'])


@app.errorhandler(404)

# inbuilt function which takes error as parameter
def not_found(e):

# defining function
  return render_template("404.html")

if __name__ == '__main__':
    # Load the model and condition details when starting the server
    model_loaded = load_ml_model()
    details_loaded = load_condition_details()
    
    if model_loaded:
        print("Starting Flask server...")
        if not details_loaded:
            print("Warning: Condition details not loaded. Will proceed without detailed information.")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to load model. Server not started.")