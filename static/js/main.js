// Main verification logic
document.addEventListener('DOMContentLoaded', function() {
    // CAPTCHA refresh function
    window.refreshCaptcha = function() {
        const captchaImg = document.getElementById('captchaImage');
        if (captchaImg) {
            captchaImg.src = '/captcha?' + new Date().getTime();
            document.getElementById('captchaInput').value = '';
        }
    };

    // Verification button handler
    const verifyBtn = document.getElementById('verifyBtn');
    if (verifyBtn) {
        verifyBtn.addEventListener('click', async function() {
            const captchaInput = document.getElementById('captchaInput');
            if (!captchaInput || !captchaInput.value.trim()) {
                alert('Please enter the CAPTCHA text');
                return;
            }

            try {
                const response = await fetch('/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'captcha=' + encodeURIComponent(captchaInput.value.trim().toUpperCase())
                });

                const result = await response.json();
                
                if (result.success) {
                    // Show success message
                    const toastEl = document.getElementById('successToast');
                    if (toastEl) {
                        const toast = new bootstrap.Toast(toastEl);
                        toast.show();
                    }

                    // Copy to clipboard if possible
                    if (navigator.clipboard && result.code) {
                        try {
                            await navigator.clipboard.writeText(result.code);
                        } catch (e) {
                            console.error('Failed to copy:', e);
                        }
                    }

                    // In a real implementation, you would redirect or proceed
                    console.log('Verification successful for domain:', result.domain);
                } else {
                    alert(result.error || 'Verification failed. Please try again.');
                    refreshCaptcha();
                }
            } catch (error) {
                console.error('Verification error:', error);
                alert('An error occurred during verification. Please try again.');
                refreshCaptcha();
            }
        });
    }

    // Auto-focus CAPTCHA input when modal shown
    const verificationModal = document.getElementById('verificationModal');
    if (verificationModal) {
        verificationModal.addEventListener('shown.bs.modal', function() {
            const captchaInput = document.getElementById('captchaInput');
            if (captchaInput) {
                captchaInput.focus();
            }
        });
    }
});
