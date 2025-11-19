// user-loader.js

// Get necessary data from localStorage
const authToken = localStorage.getItem("authToken");
const userRole = localStorage.getItem("userRole"); 
const isLoggedIn = !!authToken;

// Determine the current page for checks (normalize: strip query/search)
const currentPage = (window.location.pathname || '').split('/').pop() || 'index.html';
const currentPageNorm = currentPage.split('?')[0]; // defensive: ensure no query string

// Debug: log auth state and current page (no secrets)
try {
    console.log('[user-loader] isLoggedIn=', !!isLoggedIn, 'userRole=', userRole, 'currentPage=', currentPage);
} catch (e) { /* ignore in constrained environments */ }

// Reload-guard: detect repeated loads of the same page and suppress redirects
try {
    const guardKey = 'tii_reload_count_' + currentPage;
    const prev = sessionStorage.getItem(guardKey);
    const count = prev ? (parseInt(prev, 10) + 1) : 1;
    sessionStorage.setItem(guardKey, String(count));
    if (count > 3) {
        console.warn(`[user-loader] detected reload loop on ${currentPage} (count=${count}). Suppressing redirects.`);
        window.__tii_suppress_redirects = true;
    }
} catch (e) { /* ignore */ }

// Pages that should be inaccessible AFTER login
const loginPages = ["login.html", "register.html", "admin-login.html"];

// Pages that must be protected (requires a user to be logged in)
const studentProtectedPages = [
    // REMOVED 'index.html' from this list to make it accessible to everyone.
    "portal.html", 
    "profile.html", 
    "courses.html", 
    "other-courses.html", 
    "lessons.html",       
    "curriculum.html",    
    "feedback.html"       
];

// Admin-only pages
const adminPages = ["admin.html", "admin-portal.html", "manage-users.html"]; 


/**
 * 1. POST-LOGIN REDIRECTION (Block login pages if logged in)
 * If the user is logged in and tries to access a login-related page, send them to the main portal (index.html).
 */
if (!window.__tii_suppress_redirects && isLoggedIn && loginPages.includes(currentPageNorm)) {
    // Redirect logged-in users away from login pages to their portal (admin -> admin portal)
    const role = localStorage.getItem('userRole');
    if (role === 'admin') window.location.href = '/Tii/admin-portal.html';
    else window.location.href = '/Tii/portal.html';
}

/**
 * 2. GENERAL PAGE PROTECTION (Block unauthenticated users)
 * If NOT logged in, redirect them to login.html if they try to access any protected page.
 */
if (!window.__tii_suppress_redirects && !isLoggedIn) {
    // Combine all pages that require login (Student + Admin)
    const allProtectedPages = [...studentProtectedPages, ...adminPages];

    // Only redirect if the current page is protected AND is NOT a login page
    if (allProtectedPages.includes(currentPageNorm) && !loginPages.includes(currentPageNorm)) {
        // If already on login page (with a next param) don't redirect again — avoid loop.
        const alreadyOnLogin = /login\.html(\?|$)/.test(window.location.pathname + window.location.search);
        if (!alreadyOnLogin) {
            // Preserve the intended next path so login can redirect back after success
            const next = window.location.pathname + window.location.search;
            window.location.href = `/Tii/login.html?next=${encodeURIComponent(next)}`;
        }
    }
}

/**
 * 3. ROLE-BASED ACCESS CONTROL (Admin-only pages)
 * If the page is an admin page AND the user is not an admin, redirect them.
 */
if (!window.__tii_suppress_redirects && adminPages.includes(currentPageNorm) && userRole !== "admin") {
    // Redirect non-admins trying to access admin pages to a safe student area (absolute path)
    window.location.href = "/Tii/portal.html";
}

// --- NAV PATH NORMALIZATION & ADMIN BANNER ---
// Normalize relative header/nav links to absolute `/Tii/` paths so generated pages and nested routes resolve correctly.
(function(){
    function shouldPrefix(href){
        if (!href) return false;
        href = String(href).trim();
        if (!href) return false;
        // skip absolute/anchor/mailto/tel
        if (href.startsWith('/') || href.startsWith('http') || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return false;
        return true;
    }

    function prefixAll(){
        try{
            const sel = document.querySelectorAll('header a, nav a, footer a');
            sel.forEach(a=>{
                try{
                    const h = a.getAttribute('href');
                    if (shouldPrefix(h)) a.setAttribute('href', '/Tii/' + h);
                }catch(e){}
            });
        }catch(e){}
    }

    // Admin banner: show a small dismissible banner for admins reminding them uploads are restricted
    function parseJwt(token){
        try{
            const p = token.split('.')[1];
            if (!p) return null;
            const json = atob(p.replace(/-/g,'+').replace(/_/g,'/'));
            return JSON.parse(json);
        }catch(e){ return null; }
    }

    function showAdminBannerIfNeeded(){
        try{
            if (localStorage.getItem('tii_admin_banner_hidden')) return;
            const token = localStorage.getItem('authToken');
            const payload = token ? parseJwt(token) : null;
            if (!payload || payload.role !== 'admin') return;
            const existing = document.getElementById('tii-admin-banner');
            if (existing) return;
            const b = document.createElement('div');
            b.id = 'tii-admin-banner';
            b.style.position = 'fixed';
            b.style.top = '12px';
            b.style.right = '12px';
            b.style.zIndex = '9999';
            b.style.background = '#fff7e6';
            b.style.border = '1px solid #ffd59e';
            b.style.color = '#333';
            b.style.padding = '10px 14px';
            b.style.borderRadius = '8px';
            b.style.boxShadow = '0 4px 16px rgba(0,0,0,0.08)';
            b.innerHTML = '<strong>Admin</strong>: Uploads are restricted to administrators. <a href="/Tii/admin-portal.html" style="margin-left:8px;">Manage</a> <button id="tii-admin-banner-close" style="margin-left:10px;background:#ffd59e;border:0;padding:4px 8px;border-radius:6px;cursor:pointer">Dismiss</button>';
            document.body.appendChild(b);
            document.getElementById('tii-admin-banner-close').addEventListener('click', ()=>{ localStorage.setItem('tii_admin_banner_hidden','1'); b.remove(); });
        }catch(e){}
    }

    if (document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', ()=>{ prefixAll(); showAdminBannerIfNeeded(); });
    } else {
        prefixAll(); showAdminBannerIfNeeded();
    }
})();