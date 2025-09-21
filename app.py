from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
from utils.api_handler import VirusTotalAPI
from utils.url_analyzer import URLAnalyzer
from models.ml_model import WebGuardMLModel
import urllib.parse
from datetime import datetime
import json
import traceback  # Add this for better error debugging

load_dotenv()

app = Flask(__name__)
app.secret_key = "webguard-ai-secret-key-2024"

# Initialize components
vt_api = VirusTotalAPI()
url_analyzer = URLAnalyzer()
ml_model = WebGuardMLModel()

# Train or load ML model on startup
print("🤖 Initializing WebGuard AI ML model...")
try:
    if not ml_model.load_model():
        print("📚 Training new model...")
        accuracy = ml_model.train_model()
        print(f"✅ Model trained with accuracy: {accuracy:.3f}")
    else:
        print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Error with ML model: {e}")

# Simple in-memory storage for demonstration
scan_history = []

def clean_for_json(obj):
    """Clean object to make it JSON serializable"""
    if obj is None:
        return None
    
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    
    if isinstance(obj, dict):
        return {key: clean_for_json(value) for key, value in obj.items()}
    
    if isinstance(obj, list):
        return [clean_for_json(item) for item in obj]
    
    # Convert any other non-serializable types to string
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        print(f"❌ Template error: {e}")
        return f"Error loading template: {str(e)}", 500

@app.route('/scan', methods=['POST'])
def scan_website():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Validate and normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        print(f"🔍 Scanning URL: {url}")
        
        # Extract features for ML model
        features = url_analyzer.extract_features(url)
        print(f"📊 Extracted {len(features)} features")
        
        # Get ML prediction
        ml_prediction = ml_model.predict_risk(features)
        print(f"🤖 ML Prediction: {ml_prediction['risk_level']} ({ml_prediction['confidence']:.1f}% confidence)")
        
        # Get VirusTotal data with enhanced error handling
        virustotal_data = None
        try:
            print("🛡️ Checking VirusTotal database...")
            vt_result = vt_api.get_url_report(url)
            if vt_result:
                virustotal_data = vt_result
                print(f"📋 Found existing VT report: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)} detections")
            else:
                print("🔄 No existing report found, submitting for new scan...")
                vt_result = vt_api.scan_url(url)
                if vt_result and 'data' in vt_result and 'attributes' in vt_result['data']:
                    attrs = vt_result['data']['attributes']
                    stats = attrs.get('stats', {})
                    virustotal_data = {
                        'response_code': 1,
                        'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                        'total': sum(stats.values()) if stats else 0,
                        'scan_date': str(attrs.get('date', '')),  # Convert to string
                        'stats': stats
                    }
                    print(f"✅ New scan completed: {virustotal_data['positives']}/{virustotal_data['total']} detections")
        except Exception as e:
            print(f"⚠️ VirusTotal API error: {str(e)}")
        
        # Get domain information with JSON-safe cleanup
        domain_info = None
        try:
            domain_info = url_analyzer.get_domain_info(url)
            if domain_info:
                # Clean domain_info for JSON serialization
                domain_info = clean_for_json(domain_info)
                print(f"🌐 Domain age: {domain_info.get('age_days', 0)} days")
        except Exception as e:
            print(f"⚠️ Domain info error: {str(e)}")
        
        # Calculate overall risk score
        overall_risk = ml_prediction['risk_score']
        if virustotal_data and virustotal_data.get('positives', 0) > 0:
            overall_risk = max(overall_risk, 2)
        
        # Prepare response with JSON-safe data
        response = {
            'url': url,
            'ml_prediction': ml_prediction,
            'virustotal_data': virustotal_data,
            'domain_info': domain_info,
            'features': features,
            'overall_risk_score': overall_risk,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # ✅ Fixed: String format
            'scan_id': len(scan_history) + 1,
            'status': 'success'
        }
        
        # Clean the entire response to ensure JSON compatibility
        response = clean_for_json(response)
        
        # Store in memory for demonstration
        scan_history.append(response)
        if len(scan_history) > 100:
            scan_history.pop(0)
        
        print("✅ Scan completed successfully")
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ Scan error: {str(e)}")
        traceback.print_exc()  # Print full error traceback
        
        # Return JSON-safe error response
        error_response = {
            'error': f'Scan failed: {str(e)}',
            'status': 'error',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return jsonify(error_response), 500

@app.route('/health')
def health_check():
    try:
        return jsonify({
            'status': 'healthy',
            'model_trained': ml_model.is_trained,
            'total_scans': len(scan_history),
            'api_status': 'connected',
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/recent-scans')
def recent_scans():
    """Get recent scan history"""
    try:
        # Clean scan history for JSON serialization
        recent_scans_data = scan_history[-10:] if scan_history else []
        cleaned_scans = clean_for_json(recent_scans_data)
        
        return jsonify({
            'total_scans': len(scan_history),
            'recent_scans': cleaned_scans
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats')
def get_stats():
    """Get scanning statistics"""
    try:
        if not scan_history:
            return jsonify({'message': 'No scans performed yet'})
        
        safe_count = sum(1 for scan in scan_history if scan.get('ml_prediction', {}).get('risk_score') == 0)
        suspicious_count = sum(1 for scan in scan_history if scan.get('ml_prediction', {}).get('risk_score') == 1)
        risky_count = sum(1 for scan in scan_history if scan.get('ml_prediction', {}).get('risk_score') == 2)
        
        return jsonify({
            'total_scans': len(scan_history),
            'safe_sites': safe_count,
            'suspicious_sites': suspicious_count,
            'risky_sites': risky_count,
            'vt_detections': sum(1 for scan in scan_history 
                               if scan.get('virustotal_data') and 
                               scan['virustotal_data'].get('positives', 0) > 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting WebGuard AI...")
    print("🔗 Navigate to http://localhost:5000 to use the application")
    print("🛡️ VirusTotal API integration: ACTIVE")
    print("🤖 Machine Learning model: READY")
    app.run(debug=True, host='0.0.0.0', port=5000)
