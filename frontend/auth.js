// auth.js

// Detect API URL based on environment
const API_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3000' 
    : window.location.origin.replace(/:\d+$/, ''); // Use current domain for production

let adminEmail = ''; // Variable to store the email after Step 1

// Timer configuration for token resend
const RESEND_TIMEOUT_SECONDS = 60;
let resendTimerInterval = null;

/* ============================================
    PASSWORD TOGGLE
============================================ */
export function setupPasswordToggles() {
    document.querySelectorAll('.toggle-password').forEach(icon => {
        icon.addEventListener('click', () => {
            const targetId = icon.getAttribute('data-target');
            const targetInput = document.getElementById(targetId);
            if (targetInput) {
                const type = targetInput.getAttribute('type') === 'password' ? 'text' : 'password';
                targetInput.setAttribute('type', type);
                icon.classList.toggle('fa-eye');
                icon.classList.toggle('fa-eye-slash');
            }
        });
    });
}

/* ============================================
    AUTH BUTTON HANDLER
============================================ */
export function handleAuthButton() {
    const authButton = document.getElementById('auth-button');
    if (authButton && localStorage.getItem('authToken')) {
        authButton.textContent = 'Logout';
        authButton.href = '#';
        authButton.addEventListener('click', (e) => {
            e.preventDefault();
            logout(); // Calls the exported logout function below
        });
    } else if (authButton) {
        authButton.textContent = 'Login';
        authButton.href = 'login.html';
    }
}

/* ============================================
    LOGOUT FUNCTION
============================================ */
export function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userName');
    localStorage.removeItem('userRole');
    localStorage.removeItem('verificationEmail');
    alert('You have been logged out.');
    window.location.href = 'index.html';
}

/* ============================================
    PAGE PROTECTION (Legacy - can be removed if user-loader.js is used)
============================================ */
// This function is no longer needed since user-loader.js handles all page protection.
// You can safely remove it from here and from any module imports.
export function protectPage() {
    if (!localStorage.getItem('authToken')) {
        alert('You must be logged in to view this page.');
        window.location.href = 'login.html';
    }
}

/* ============================================
    REGISTRATION
============================================ */
export function handleRegistration() {
    const form = document.getElementById('registration-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const password = form['password'].value;
        const confirmPassword = form['confirm_password'].value;
        const passwordErrorDiv = document.getElementById('password-match-error');
        const errorElement = document.getElementById('registration-error');

        if (errorElement) errorElement.textContent = '';

        if (password !== confirmPassword) {
            passwordErrorDiv.style.display = 'block';
            form['confirm_password'].focus();
            return;
        } else {
            passwordErrorDiv.style.display = 'none';
        }

        const fullName = form['full_name'].value;
        const email = form['email'].value;
        const terms = form['terms'].checked;

        if (!terms) {
            alert("You must agree to the Terms of Service.");
            return;
        }

        try {
            const response = await fetch(`${API_URL}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ full_name: fullName, email, password }),
            });

            const result = await response.json();

            if (response.ok) {
                alert(result.message);
                localStorage.setItem('verificationEmail', email);
                // If server returned an OTP in dev mode, save it so the OTP page can display it.
                if (result.otp) {
                    localStorage.setItem('debug_otp', result.otp);
                } else {
                    localStorage.removeItem('debug_otp');
                }
                window.location.href = 'otp-verification.html';
            } else {
                if (errorElement) errorElement.textContent = `Registration Failed: ${result.message}`;
            }
        } catch (error) {
            console.error('Registration Network Error:', error);
            if (errorElement) errorElement.textContent = 'A network error occurred.';
        }
    });
}

/* ============================================
    LOGIN (Student)
============================================ */
export function handleLogin() {
    const form = document.getElementById('login-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = form['email'].value;
        const password = form['password'].value;
        const errorElement = document.getElementById('login-error');
        if (errorElement) errorElement.textContent = '';

        try {
            const response = await fetch(`${API_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });

            const result = await response.json();

            if (response.ok && result.status === 'success') {
                localStorage.setItem('authToken', result.authToken);
                localStorage.setItem('userName', result.full_name);
                localStorage.setItem('userRole', result.role);

                handleAuthButton();

                // Redirect based on role
                if (result.role === 'admin') {
                    window.location.href = 'admin-portal.html';
                } else {
                    window.location.href = 'portal.html';
                }
            } else if (response.status === 403 && result.action === 'redirect_to_otp') {
                localStorage.setItem('verificationEmail', email);
                window.location.href = 'otp-verification.html';
            } else {
                if (errorElement) errorElement.textContent = `Login Failed: ${result.message}`;
            }
        } catch (error) {
            console.error('Login Network Error:', error);
            if (errorElement) errorElement.textContent = 'A network error occurred.';
        }
    });
}

/* ============================================
    OTP VERIFICATION
============================================ */
export function handleOTPVerification() {
    const verificationForm = document.getElementById('otp-verification-form');
    const resendButton = document.getElementById('resend-otp-button');
    const emailDisplay = document.getElementById('verification-email-display');
    const errorElement = document.getElementById('verification-error');
    const email = localStorage.getItem('verificationEmail');

    if (!email) {
        alert("Verification link expired. Please log in again.");
        window.location.href = 'login.html';
        return;
    }

    if (emailDisplay) emailDisplay.textContent = email;

    // If a debug OTP was saved (development only), show it on the page for easier testing
    const debugOtp = localStorage.getItem('debug_otp');
    if (debugOtp) {
        let debugDiv = document.getElementById('debug-otp-display');
        if (!debugDiv) {
            debugDiv = document.createElement('div');
            debugDiv.id = 'debug-otp-display';
            debugDiv.style.marginTop = '1rem';
            debugDiv.style.padding = '0.5rem';
            debugDiv.style.background = '#fff7e6';
            debugDiv.style.border = '1px solid #ffd27a';
            debugDiv.style.borderRadius = '4px';
            debugDiv.style.color = '#663c00';
            debugDiv.style.fontWeight = '600';

            if (verificationForm) {
                verificationForm.parentNode.insertBefore(debugDiv, verificationForm.nextSibling);
            } else {
                document.body.appendChild(debugDiv);
            }
        }
        debugDiv.textContent = `DEV OTP (only shown in non-production): ${debugOtp}`;
    }

    if (verificationForm) {
        verificationForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const otpCode = document.getElementById('otp_code').value;
            if (!otpCode) {
                errorElement.textContent = 'Please enter the 6-digit code.';
                return;
            }

            try {
                const response = await fetch(`${API_URL}/verify-otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, otp_code: otpCode }),
                });

                const result = await response.json();

                if (response.ok) {
                    alert(result.message);
                    localStorage.removeItem('verificationEmail');
                    localStorage.removeItem('debug_otp');
                    localStorage.setItem('authToken', result.authToken);
                    localStorage.setItem('userName', result.full_name);
                    localStorage.setItem('userRole', result.role);

                    handleAuthButton();
                    window.location.href = 'portal.html';
                } else {
                    errorElement.textContent = `Verification Failed: ${result.message}`;
                }
            } catch (error) {
                console.error('OTP Error:', error);
                errorElement.textContent = 'A network error occurred.';
            }
        });
    }

    if (resendButton) {
        resendButton.addEventListener('click', async () => {
            errorElement.textContent = 'Sending new code...';
            try {
                const response = await fetch(`${API_URL}/resend-otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email }),
                });

                const result = await response.json();
                errorElement.textContent = result.message;
            } catch {
                errorElement.textContent = 'Network error while resending OTP.';
            }
        });
    }
}

/* ============================================
    HELPER: DISPLAY ADMIN ERROR
============================================ */
function displayAdminError(message) {
    const errorElement = document.getElementById('admin-login-error');
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = message ? 'block' : 'none'; // Only show if there's a message
    }
}

/* ============================================
    RESEND TIMER LOGIC
============================================ */
function startResendTimer() {
    const resendButton = document.getElementById('resend-token-btn');
    const timerDisplay = document.getElementById('resend-timer');
    let timeLeft = RESEND_TIMEOUT_SECONDS;

    // Clear any existing interval
    if (resendTimerInterval) {
        clearInterval(resendTimerInterval);
    }
    
    // Disable button and show timer immediately
    resendButton.disabled = true;
    timerDisplay.textContent = `Resend in ${timeLeft}s`;

    resendTimerInterval = setInterval(() => {
        timeLeft--;
        timerDisplay.textContent = `Resend in ${timeLeft}s`;

        if (timeLeft <= 0) {
            clearInterval(resendTimerInterval);
            resendButton.disabled = false;
            timerDisplay.textContent = 'Ready to Resend';
        }
    }, 1000);
}

/* ============================================
    ADMIN TOKEN SEND
============================================ */
export async function sendAdminToken(email) {
    displayAdminError(''); // Clear error

    try {
        const response = await fetch(`${API_URL}/send_admin_token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // Send the email captured from Step 1
            body: JSON.stringify({ email }),
        });

        const data = await response.json();
        if (response.ok) {
            displayAdminError(`✅ ${data.message}`);
        } else {
            displayAdminError(`❌ ${data.message}`);
        }
    } catch (error) {
        console.error('Error sending admin token:', error);
        displayAdminError('Failed to send token.');
    }
}


/* ============================================
    ADMIN LOGIN STEP 1: CREDENTIALS CHECK
============================================ */
async function handleAdminLoginStep1(event) {
    event.preventDefault();
    displayAdminError(''); // Clear previous errors

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();

    if (!email || !password) {
        displayAdminError('Please enter both email and password.');
        return;
    }

    // Store email globally for Step 2 and Resend Token
    adminEmail = email;

    const step1Form = document.getElementById('admin-login-step1-form');
    const step2Form = document.getElementById('admin-login-step2-form');

    try {
        // New endpoint for credential check
        const response = await fetch(`${API_URL}/admin_login_check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        const result = await response.json();

        if (response.ok && result.action === 'login_success') {
            // Case 1: Already an Admin - Direct Login
            localStorage.setItem('authToken', result.authToken);
            localStorage.setItem('userName', result.full_name);
            localStorage.setItem('userRole', result.role);
            window.location.href = 'admin-portal.html';
        } else if (response.status === 403 && result.action === 'require_token') {
            // Case 2: Credentials correct, but token required (e.g., student trying to become admin)
            displayAdminError("Credentials accepted. A one-time admin token has been requested. Please check the Admin Email.");
            
            // Hide Step 1, Show Step 2
            step1Form.classList.add('hidden');
            step2Form.classList.remove('hidden');
            
            // Immediately send the first token and start the timer
            await sendAdminToken(adminEmail);
            startResendTimer();
        } else {
            // Case 3: General login failure (401)
            displayAdminError(`Login Failed: ${result.message}`);
        }
    } catch (error) {
        console.error('Admin Login Step 1 Network Error:', error);
        displayAdminError('A network error occurred.');
    }
}


/* ============================================
    ADMIN LOGIN STEP 2: TOKEN VERIFICATION
============================================ */
async function handleAdminTokenVerification(event) {
    event.preventDefault();
    displayAdminError(''); // Clear previous errors

    const token = document.getElementById('token').value.trim();
    // Get password from the now-hidden input (adminEmail is global)
    const password = document.getElementById('password').value.trim(); 

    if (!token) {
        displayAdminError('Please enter the Admin Token.');
        return;
    }
    
    // Final verification with email, password, and token
    try {
        const response = await fetch(`${API_URL}/admin_login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: adminEmail, password, token }),
        });

        const result = await response.json();

        if (response.ok) {
            // Login success - token verified, role possibly upgraded
            localStorage.setItem('authToken', result.authToken);
            localStorage.setItem('userName', result.full_name);
            localStorage.setItem('userRole', result.role);
            window.location.href = 'admin-portal.html';
        } else {
            // Token verification failure
            displayAdminError(`Verification Failed: ${result.message}`);
        }
    } catch (error) {
        console.error('Admin Token Verification Network Error:', error);
        displayAdminError('A network error occurred.');
    }
}

/* ============================================
    PROFILE FETCH (Unchanged)
============================================ */
export async function handleProfileFetch() {
    const userName = localStorage.getItem('userName') || 'Student';
    const welcomeText = document.getElementById('welcome-text');
    if (welcomeText) welcomeText.textContent = `👋 Welcome, ${userName.split(' ')[0]}!`;
}

/* ============================================
    PORTAL LINK SWITCH (Student ↔ Admin) (Unchanged)
============================================ */
export function updatePortalLink() {
    const nav = document.querySelector('.main-nav');
    if (!nav) return;

    const userRole = localStorage.getItem('userRole');
    const portalLink = Array.from(nav.querySelectorAll('a')).find(a =>
        a.textContent.includes('Portal')
    );

    if (!portalLink) return;

    if (userRole === 'admin') {
        portalLink.textContent = 'Admin Portal';
        portalLink.href = 'admin-portal.html';
    } else {
        portalLink.textContent = 'Student Portal';
        portalLink.href = 'portal.html';
    }
}


/* ============================================
    INIT ADMIN LOGIN PAGE
============================================ */
export function initializeAdminLogin() {
    setupPasswordToggles();
    
    const step1Form = document.getElementById('admin-login-step1-form');
    const step2Form = document.getElementById('admin-login-step2-form');
    const resendButton = document.getElementById('resend-token-btn');
    
    // Ensure forms are correctly initialized (Step 1 visible, Step 2 hidden)
    if (step1Form && step2Form) {
        // We ensure Step 2 is hidden initially, in case of browser back button behavior
        step1Form.classList.remove('hidden');
        step2Form.classList.add('hidden');
    }
    
    // Attach event listeners
    if (step1Form) {
        step1Form.addEventListener('submit', handleAdminLoginStep1);
    }
    
    if (step2Form) {
        step2Form.addEventListener('submit', handleAdminTokenVerification);
    }
    
    if (resendButton) {
        // Corrected: Use async callback for await
        resendButton.addEventListener('click', async () => {
            if (adminEmail) {
                await sendAdminToken(adminEmail); // Ensure we wait for the send operation
                startResendTimer();
            } else {
                displayAdminError('Please complete Step 1 first.');
            }
        });
    }
}