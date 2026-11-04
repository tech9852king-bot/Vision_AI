/**
 * VantaVisionAI - Firebase Cloud Firestore & Authentication Client Module
 * Grounded in firebase-applet-config.json with zero-trust error handling
 */
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js';
import {
  getAuth,
  onAuthStateChanged,
  signInWithPopup,
  GoogleAuthProvider,
  signOut
} from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js';
import {
  initializeFirestore,
  getFirestore,
  doc,
  collection,
  addDoc,
  getDocFromServer,
  serverTimestamp
} from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js';

const firebaseConfig = {
  projectId: "gen-lang-client-0628849129",
  appId: "1:305178074380:web:a61d7835be947bc1fa7d29",
  apiKey: "AIzaSyB1QVHOoWMxOwcgo-BUK6RfcA-pxcvItcI",
  authDomain: "gen-lang-client-0628849129.firebaseapp.com",
  firestoreDatabaseId: "ai-studio-vantavisionai-41676fcb-440e-4810-909c-de0f999fe055",
  storageBucket: "gen-lang-client-0628849129.firebasestorage.app",
  messagingSenderId: "305178074380",
  measurementId: "",
  oAuthClientId: "305178074380-ve6jleso6q1s1eiepdi8vbdon1p96jm8.apps.googleusercontent.com",
  recaptchaSiteKey: ""
};

let app = null;
let auth = null;
let db = null;
let currentUser = null;
let isConnected = false;

// Structured Error Handler conforming to Firebase Skill guidelines
function handleFirestoreError(error, operationType, path) {
  const errInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth?.currentUser?.uid || null,
      email: auth?.currentUser?.email || null,
      emailVerified: auth?.currentUser?.emailVerified || null,
      isAnonymous: auth?.currentUser?.isAnonymous || false,
      tenantId: auth?.currentUser?.tenantId || null,
      providerInfo: auth?.currentUser?.providerData?.map(p => ({
        providerId: p.providerId,
        email: p.email
      })) || []
    },
    operationType,
    path
  };
  console.warn('[VantaVisionAI Firebase Error]:', JSON.stringify(errInfo));
  return errInfo;
}

try {
  app = initializeApp(firebaseConfig);
  auth = getAuth(app);
  try {
    db = initializeFirestore(app, {
      experimentalAutoDetectLongPolling: true
    }, firebaseConfig.firestoreDatabaseId);
  } catch (_) {
    db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
  }

  // Validate connection to Firestore per skill mandate
  (async function testConnection() {
    try {
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('the client is offline or timed out')), 4000)
      );
      await Promise.race([
        getDocFromServer(doc(db, 'test', 'connection')),
        timeoutPromise
      ]);
      isConnected = true;
      console.log('[VantaVisionAI] Firebase Firestore online & connected.');
    } catch (error) {
      if (error instanceof Error && (error.message.includes('offline') || error.message.includes('timed out') || error.message.includes('Could not reach'))) {
        console.warn('[VantaVisionAI] Firebase operating in local/offline mode. Local SQLite active.');
      } else {
        console.warn('[VantaVisionAI] Firebase connection check status:', error.message || error);
      }
    }
  })();

  // Listen to auth state transitions
  onAuthStateChanged(auth, (user) => {
    currentUser = user;
    updateAuthUi(user);
  });
} catch (e) {
  console.warn('[VantaVisionAI] Firebase initialization deferred:', e.message);
}

function updateAuthUi(user) {
  const avatarEl = document.getElementById('user-avatar');
  const nameEl = document.getElementById('user-display-name');
  const roleEl = document.getElementById('user-role-label');
  const btnAuth = document.getElementById('btn-auth-action');

  if (user) {
    if (avatarEl) {
      if (user.photoURL) {
        avatarEl.innerHTML = `<img src="${user.photoURL}" alt="avatar" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`;
      } else {
        const initials = (user.displayName || user.email || 'OP').substring(0, 2).toUpperCase();
        avatarEl.textContent = initials;
      }
    }
    if (nameEl) nameEl.textContent = user.displayName || user.email.split('@')[0];
    if (roleEl) {
      const isAdmin = user.email === 'tech9852king@gmail.com';
      roleEl.textContent = isAdmin ? 'Super Admin (Cloud)' : 'Verified Operator';
      roleEl.style.color = isAdmin ? 'var(--accent-cyan)' : 'var(--accent-emerald)';
    }
    if (btnAuth) {
      btnAuth.textContent = 'Sign Out';
      btnAuth.className = 'btn btn-sm mono';
    }
  } else {
    if (avatarEl) avatarEl.textContent = 'OP';
    if (nameEl) nameEl.textContent = 'local_operator';
    if (roleEl) {
      roleEl.textContent = 'Local Mode';
      roleEl.style.color = 'var(--text-dim)';
    }
    if (btnAuth) {
      btnAuth.textContent = 'Sign In';
      btnAuth.className = 'btn btn-sm btn-primary mono';
    }
  }
}

async function signIn() {
  if (!auth) return;
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  try {
    const cred = await signInWithPopup(auth, provider);
    if (window.showToast) {
      window.showToast(`Signed in as ${cred.user.email}`, 'success');
    }
    return cred.user;
  } catch (err) {
    console.warn('[Firebase Auth] Sign in cancelled or failed:', err.message);
    if (window.showToast) {
      window.showToast(`Authentication notice: ${err.message}`, 'warning');
    }
  }
}

async function handleSignOut() {
  if (!auth) return;
  try {
    await signOut(auth);
    if (window.showToast) {
      window.showToast('Signed out of cloud session. Operating in local mode.', 'info');
    }
  } catch (err) {
    console.error('Sign out error:', err);
  }
}

// Cloud Synchronization API for Detection Events
async function syncDetectionEvent(ev) {
  if (!db || !currentUser) return null;
  const path = 'events';
  try {
    const docRef = await addDoc(collection(db, path), {
      tenantId: ev.tenantId || 'default',
      cameraId: ev.camera_id || 'BROWSER-SCANNER',
      className: ev.class_name || 'unknown',
      confidence: Number(ev.confidence) || 0.85,
      timestamp: new Date().toISOString(),
      createdAt: serverTimestamp()
    });
    return docRef.id;
  } catch (err) {
    handleFirestoreError(err, 'create', path);
    return null;
  }
}

// Cloud Synchronization API for Security Incidents
async function syncIncident(inc) {
  if (!db || !currentUser) return null;
  const path = 'incidents';
  try {
    const docRef = await addDoc(collection(db, path), {
      tenantId: inc.tenantId || 'default',
      title: inc.title || 'Security Alert',
      severity: inc.severity || 'MEDIUM',
      status: inc.status || 'OPEN',
      cameraId: inc.cameraId || 'BROWSER-SCANNER',
      details: inc.details || '',
      timestamp: new Date().toISOString(),
      createdAt: serverTimestamp()
    });
    return docRef.id;
  } catch (err) {
    handleFirestoreError(err, 'create', path);
    return null;
  }
}

// Attach click listener for Auth Button
document.addEventListener('DOMContentLoaded', () => {
  const btnAuth = document.getElementById('btn-auth-action');
  if (btnAuth) {
    btnAuth.addEventListener('click', () => {
      if (currentUser) {
        handleSignOut();
      } else {
        signIn();
      }
    });
  }
});

// Export globally on window for seamless integration with static/app.js
window.VantaFirebase = {
  app,
  auth,
  db,
  getCurrentUser: () => currentUser,
  isConnected: () => isConnected,
  signIn,
  signOut: handleSignOut,
  syncDetectionEvent,
  syncIncident
};
