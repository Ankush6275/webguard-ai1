// Simplified app.js - Guaranteed to work
console.log('🚀 WebGuard AI JavaScript Loading...');

document.addEventListener('DOMContentLoaded', function() {
    console.log('✅ DOM loaded, setting up form handler');
    
    const form = document.getElementById('scanForm');
    
    if (!form) {
        console.error('❌ Form not found!');
        return;
    }
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        console.log('📝 Form submitted!');
        
        const urlInput = document.getElementById('url');
        const url = urlInput.value;
        
        console.log('🔍 URL to scan:', url);
        
        // Show simple loading message
        document.body.innerHTML += `
            <div id="simpleResults" style="margin: 20px; padding: 20px; border: 2px solid #007bff; border-radius: 10px; background: #f8f9fa;">
                <h3>🔄 Scanning: ${url}</h3>
                <p>Please wait...</p>
            </div>
        `;
        
        // Make the request
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({url: url})
        })
        .then(response => {
            console.log('📡 Response received:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('✅ Data received:', data);
            
            // Show results
            document.getElementById('simpleResults').innerHTML = `
                <h3>✅ Scan Complete!</h3>
                <p><strong>URL:</strong> ${data.url}</p>
                <p><strong>Risk Level:</strong> ${data.ml_prediction.risk_level}</p>
                <p><strong>Confidence:</strong> ${data.ml_prediction.confidence.toFixed(1)}%</p>
                <p><strong>Status:</strong> Analysis completed successfully</p>
            `;
        })
        .catch(error => {
            console.error('❌ Error:', error);
            document.getElementById('simpleResults').innerHTML = `
                <h3>❌ Error</h3>
                <p>Failed to scan website: ${error.message}</p>
                <p>Check console for details</p>
            `;
        });
    });
    
    console.log('✅ Form handler set up successfully');
});
