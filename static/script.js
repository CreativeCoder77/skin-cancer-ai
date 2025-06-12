let currentResults = null;

function toggleTheme() {
    const body = document.body;
    const button = document.querySelector('.theme-toggle');

    if (body.getAttribute('data-theme') === 'light') {
        body.setAttribute('data-theme', 'dark');
        button.textContent = '☀️ Light Mode';
    } else {
        body.setAttribute('data-theme', 'light');
        button.textContent = '🌙 Dark Mode';
    }
}

function switchTab(tabName) {
    // Remove active class from all tabs and contents
    document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

    // Add active class to clicked tab and corresponding content
    event.target.classList.add('active');
    document.getElementById(tabName + '-tab').classList.add('active');
}

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    // Show loading
    showLoading();

    const formData = new FormData();
    formData.append('file', file);

    fetch('/predict', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            hideLoading();
            if (data.success) {
                currentResults = data;
                displayResults(data);
            } else {
                showError(data.error || 'An error occurred during analysis');
            }
        })
        .catch(error => {
            hideLoading();
            showError('Network error: ' + error.message);
        });
}

function showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.querySelectorAll('.tab-content').forEach(content => {
        if (content.id !== 'loading') content.style.display = 'none';
    });
}

function hideLoading() {
    document.getElementById('loading').style.display = 'none';
    document.querySelectorAll('.tab-content').forEach(content => {
        content.style.display = 'block';
    });
}

function showError(message) {
    const overviewTab = document.getElementById('overview-tab');
    overviewTab.innerHTML = `
        <div class="placeholder">
            <div class="placeholder-icon" style="color: var(--danger-color);">⚠️</div>
            <h3>Analysis Error</h3>
            <p>${message}</p>
        </div>
    `;
}

function displayResults(data) {
    displayOverview(data);
    displayProbabilities(data);
    displayInformation(data);
    displayNextSteps(data);
}



function displayOverview(data) {
    console.log("Classification data:", data.classification); // Debug log

    const confidence = data.top_prediction.confidence;
    const confidenceClass = confidence >= 0.7 ? 'confidence-high' :
        confidence >= 0.4 ? 'confidence-medium' : 'confidence-low';

    const overviewTab = document.getElementById('overview-tab');

    // Enhanced classification HTML generation with Learn button
    const classificationHtml = data.classification && data.classification.classification && data.classification.classification !== 'Unknown'
        ? `<div class="classification-section">
        <div class="classification-header">
            <div class="classification-info">
                <strong class="classification-label">Classification:</strong>
                <span class="classification-value ${data.classification.classification.toLowerCase().replace('-', '')}">${data.classification.classification}</span>
            </div>
            <button class="learn-btn" onclick="showClassificationInfo('${data.classification.classification}')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <path d="M9,9h6v6H9z"></path>
                    <path d="M9,9a3,3 0 0 1 6,0"></path>
                </svg>
                Learn
            </button>
        </div>
    </div>`
        : '';

    overviewTab.innerHTML = `
<div class="prediction-card">
    <div class="prediction-header">
        <div class="prediction-title">${data.top_prediction.class}</div>
        <div class="confidence-badge ${confidenceClass}">
            ${Math.round(confidence * 100)}% Confidence
        </div>
    </div>
    <img src="data:image/jpeg;base64,${data.image}" alt="Uploaded image" class="image-preview">
    ${classificationHtml}
    <p><strong>Primary Diagnosis:</strong> ${data.top_prediction.class}</p>
</div>

`;
}

// Function to show classification information
function showClassificationInfo(classification) {
    const modal = document.getElementById('classification-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-content-body');

    // Classification definitions
    const classificationInfo = {
        'benign': {
            title: 'Benign',
            definition: 'A benign condition is non-cancerous and not harmful. These conditions do not spread to other parts of the body and are generally not life-threatening.',
            characteristics: [
                'Non-cancerous growth or condition',
                'Does not invade nearby tissues',
                'Does not spread (metastasize) to other parts of the body',
                'Usually grows slowly',
                'Generally not life-threatening'
            ],
            examples: 'Examples include Melanocytic Nevus (moles), Dermatofibroma, Benign Keratosis, and Vascular Lesions.',
            color: '#10b981'
        },
        'non-cancerous': {
            title: 'Non-Cancerous',
            definition: 'Non-cancerous skin conditions are not related to cancer and are typically caused by infections, inflammation, or other benign processes.',
            characteristics: [
                'Not related to cancer',
                'Often caused by infections or inflammation',
                'Generally treatable with appropriate medication',
                'Does not spread to other body parts',
                'May be contagious (in case of infections)'
            ],
            examples: 'Examples include Tinea (Ringworm), Candidiasis (fungal infections), and Atopic Dermatitis (eczema).',
            color: '#3b82f6'
        },
        'cancer': {
            title: 'Cancer',
            definition: 'Cancerous skin conditions are malignant growths that can spread to other parts of the body and are potentially life-threatening.',
            characteristics: [
                'Malignant (cancerous) growth',
                'Can invade nearby tissues',
                'May spread (metastasize) to other body parts',
                'Requires immediate medical attention',
                'Early detection improves treatment outcomes'
            ],
            examples: 'Examples include Melanoma and Squamous Cell Carcinoma.',
            color: '#ef4444'
        },
        'precancerous': {
            title: 'Precancerous',
            definition: 'Precancerous conditions have the potential to become cancerous over time but are not yet malignant. Early treatment can prevent cancer development.',
            characteristics: [
                'Not currently cancerous',
                'Has potential to become malignant',
                'Requires monitoring and often treatment',
                'Early intervention can prevent cancer development',
                'Regular dermatological follow-up is essential'
            ],
            examples: 'Examples include Actinic Keratosis, which can develop into Squamous Cell Carcinoma if left untreated.',
            color: '#f59e0b'
        },
        // Legacy support for older classifications
        'malignant': {
            title: 'Malignant',
            definition: 'A malignant condition refers to cancerous growth that can spread to other parts of the body and is potentially life-threatening.',
            characteristics: [
                'Cancerous growth',
                'Can invade nearby tissues',
                'May spread (metastasize) to other body parts',
                'Often grows rapidly',
                'Requires immediate medical attention'
            ],
            examples: 'Examples include melanoma, basal cell carcinoma, and squamous cell carcinoma.',
            color: '#ef4444'
        },
        'pre-malignant': {
            title: 'Pre-malignant',
            definition: 'Pre-malignant conditions have the potential to become cancerous over time but are not yet malignant.',
            characteristics: [
                'Not currently cancerous',
                'Has potential to become malignant',
                'Requires monitoring and sometimes treatment',
                'Early intervention can prevent cancer development',
                'Regular follow-up is important'
            ],
            examples: 'Examples include actinic keratosis and some types of dysplastic nevi.',
            color: '#f59e0b'
        }
    };

    const info = classificationInfo[classification.toLowerCase().replace('-', '')] || {
        title: classification,
        definition: 'Classification information not available for this condition.',
        characteristics: [],
        examples: '',
        color: '#6b7280'
    };

    modalTitle.textContent = info.title;
    modalBody.innerHTML = `
<div class="classification-explanation">
    <div class="definition-section">
        <h4>Definition:</h4>
        <p>${info.definition}</p>
    </div>
    
    ${info.characteristics.length > 0 ? `
        <div class="characteristics-section">
            <h4>Key Characteristics:</h4>
            <ul class="characteristics-list">
                ${info.characteristics.map(char => `<li>${char}</li>`).join('')}
            </ul>
        </div>
    ` : ''}
    
    ${info.examples ? `
        <div class="examples-section">
            <h4>Common Conditions:</h4>
            <p>${info.examples}</p>
        </div>
    ` : ''}
    
    <div class="skin-conditions-reference">
        <h4>Specific Skin Conditions by Classification:</h4>
        <div class="conditions-grid">
            <div class="condition-group benign-group">
                <h5>Benign</h5>
                <ul>
                    <a href="/disease/vascular-lesion" style="text-decoration: none;"><li>Vascular Lesion</li></a>
                    <a href="/disease/Dermatofibroma" style="text-decoration: none;"><li>Dermatofibroma</li></a>
                    <a href="/disease/Melanocytic-Nevus" style="text-decoration: none;"><li>Melanocytic Nevus (Moles)</li></a>
                    <a href="/disease/Benign-Keratosis" style="text-decoration: none;"><li>Benign Keratosis</li></a>
                </ul>
            </div>
            
            <div class="condition-group non-cancerous-group">
                <h5>Non-Cancerous</h5>
                <ul>
                    <a href="/disease/tinea-ringworm-candidiasis" style="text-decoration: none;"><li>Tinea (Ringworm) Candidiasis</li></a>
                    <a href="/disease/atopic-dermatitis" style="text-decoration: none;"><li>Atopic Dermatitis</li></a>
                </ul>
            </div>
            
            <div class="condition-group cancer-group">
                <h5>Cancer</h5>
                <ul>
                    <a href="/disease/melanoma" style="text-decoration: none;"><li>Melanoma</li></a>
                    <a href="/disease/squamous-cell-carcinoma" style="text-decoration: none;"><li>Squamous Cell Carcinoma</li></a>
                </ul>
            </div>
            
            <div class="condition-group precancerous-group">
                <h5>Precancerous</h5>
                <ul>
                    <a href="/disease/actinic-keratosis" style="text-decoration: none;"><li>Actinic Keratosis</li></a>
                </ul>
            </div>
        </div>
    </div>
    
    <div class="disclaimer">
        <p><strong>Important:</strong> This information is for educational purposes only. Always consult with a healthcare professional for proper diagnosis and treatment.</p>
    </div>
</div>
`;

    modal.style.display = 'block';
}

// Function to close the modal
function closeClassificationModal() {
    const modal = document.getElementById('classification-modal');
    modal.style.display = 'none';
}

// Close modal when clicking outside of it
window.onclick = function (event) {
    const modal = document.getElementById('classification-modal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
}
console.log("Full response from Flask:", data);



function displayProbabilities(data) {
    const probabilitiesTab = document.getElementById('probabilities-tab');
    const topPredictions = data.all_confidences.slice(0, 5);

    const probabilitiesHTML = topPredictions.map(pred => {
        // Generate URL in JavaScript
        const diseaseSlug = pred.class.replace(/\s+/g, '-').toLowerCase();
        const url = `/disease/${diseaseSlug}`; // Adjust this path to match your routing
        
        return `
            <div class="probability-item">
                <div>
                    <a href="${url}" class="prob-item"><strong>${pred.class}</strong></a>
                    <div>${Math.round(pred.percentage)}%</div>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill" style="width: ${pred.percentage}%"></div>
                </div>
            </div>
        `;
    }).join('');
    
    probabilitiesTab.innerHTML = probabilitiesHTML;


    probabilitiesTab.innerHTML = `
        <h3>Top 5 Predictions</h3>
        <div class="probabilities-list">
            ${probabilitiesHTML}
        </div>
    `;
}

function displayInformation(data) {
    const informationTab = document.getElementById('information-tab');
    const details = data.top_prediction.details;

    if (details) {
        informationTab.innerHTML = `
            <div class="info-grid">
                ${details.causes ? `
                    <div class="info-card">
                        <h4>Possible Causes</h4>
                        <ul>
                            ${details.causes.map(cause => `<li>${cause}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${details.potential_harms ? `
                    <div class="info-card">
                        <h4>Potential Concerns</h4>
                        <ul>
                            ${details.potential_harms.map(harm => `<li>${harm}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${details.possible_progression ? `
                    <div class="info-card">
                        <h4>Possible Progression</h4>
                        <ul>
                            ${details.possible_progression.map(prog => `<li>${prog}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    } else {
        informationTab.innerHTML = `
            <div class="placeholder">
                <div class="placeholder-icon">📚</div>
                <h3>Limited information available</h3>
                <p>Please consult a healthcare professional for detailed information about this condition</p>
            </div>
        `;
    }
}

function displayNextSteps(data) {
    const nextStepsTab = document.getElementById('nextsteps-tab');
    const confidence = data.top_prediction.confidence;

    let recommendations = [];

    if (confidence < 0.3) {
        recommendations = [
            "The analysis shows low confidence - please retake the image with better lighting",
            "Ensure the affected area is clearly visible and in focus",
            "Consider taking multiple photos from different angles",
            "Consult a dermatologist for professional evaluation"
        ];
    } else if (confidence < 0.7) {
        recommendations = [
            "The analysis shows moderate confidence in the diagnosis",
            "Monitor the condition for any changes",
            "Consider consulting a healthcare provider if symptoms persist",
            "Take photos regularly to track progression",
            "Avoid self-medication without professional guidance"
        ];
    } else {
        recommendations = [
            "The analysis shows high confidence in the diagnosis",
            "Consult a dermatologist to confirm the diagnosis",
            "Follow proper skincare routine as recommended by professionals",
            "Monitor for any changes in appearance or symptoms",
            "Seek immediate medical attention if condition worsens"
        ];
    }

    nextStepsTab.innerHTML = `
        <div class="info-card">
            <h4>Recommended Actions</h4>
            <ul>
                ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
        <div class="info-card" style="margin-top: 1.5rem;">
            <h4>Important Reminders</h4>
            <ul>
                <li>This AI analysis is not a substitute for professional medical advice</li>
                <li>Always consult qualified healthcare providers for diagnosis and treatment</li>
                <li>Seek immediate medical attention for rapidly changing or concerning symptoms</li>
                <li>Keep a record of symptoms and their progression over time</li>
            </ul>
        </div>
    `;
}
document.addEventListener('DOMContentLoaded', () => {
    const uploadArea = document.querySelector('.upload-area');

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            document.getElementById('fileInput').files = files;
            handleFileUpload({ target: { files: files } });
        }
    });
});
