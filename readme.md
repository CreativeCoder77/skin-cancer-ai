
# 🧠 Skin Cancer Detection AI

## 🔍 Overview

This project uses an AI-powered image classification model to detect the presence of **skin cancer** from an uploaded image. It also provides detailed information about various **cancer-causing skin diseases**, including their severity and whether they are harmful.

## 🚀 Features

* 📷 **Image Upload & Detection**
  Upload a skin lesion image to detect if it is cancerous or not using a trained AI classification model.

* 🧬 **Disease Information**
  Learn about different types of skin diseases that can lead to cancer.

* ⚠️ **Cancer Risk Assessment**
  Get insights into the nature of the detected cancer — whether it's **benign** (not harmful) or **malignant** (harmful).

## 🧠 Technology Stack

* **Frontend:** HTML/CSS, JavaScript (or Streamlit/Flask if applicable)
* **Backend:** Python
* **AI Model:** Convolutional Neural Network (CNN) trained on skin lesion datasets (e.g., HAM10000)
* **Libraries:** TensorFlow / Keras, OpenCV, NumPy, Pandas, Matplotlib

## 📁 Project Structure

```
skin-cancer-ai/
│
├── Rash_Models/                         # Folder for trained AI models
│
├── static/                              # Static files (images, styles, JS)
│   ├── dataset/
│   │   ├── Actinic keratosis/
│   │   ├── Atopic Dermatitis/
│   │   ├── Benign keratosis/
│   │   ├── Dermatofibroma/
│   │   ├── Melanocytic nevus/
│   │   ├── Melanoma/
│   │   ├── Squamous cell carcinoma/
│   │   ├── Tinea Ringworm Candidiasis/
│   │   └── Vascular lesion/
│   ├── details.css
│   ├── script.js
│   └── styles.css
│
├── templates/                           # HTML templates
│   ├── 404.html
│   ├── details.html
│   ├── disease_database.html
│   ├── index.html
│   ├── layout.html
│
├── app.py                               # Main application 
├── details.json                         # Disease info JSON
```

## 🧪 How to Use

1. Clone this repository:

   ```bash
   https://github.com/CreativeCoder77/skin-cancer-ai.git
   cd skin-cancer-ai
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the app:

   ```bash
   python app.py
   ```

4. Open your browser and go to `http://localhost:5000`

## 📖 Future Improvements

* Multilingual disease information
* User health history integration


⚠️ Disclaimer

> This tool is for **educational** and **preliminary diagnostic** purposes only. Always consult a certified dermatologist or healthcare provider for medical decisions.


---
