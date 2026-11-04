/**
 * VantaVisionAI - Firebase Cloud Integration Verification Suite
 */
const fs = require('fs');
const path = require('path');

let passed = 0;
let total = 0;

function assert(description, condition) {
  total++;
  if (condition) {
    passed++;
    console.log(`  ✓ [PASS] ${description}`);
  } else {
    console.error(`  ✗ [FAIL] ${description}`);
    process.exitCode = 1;
  }
}

async function runSuite() {
  console.log('[TEST SUITE] Executing Firebase Cloud Integration Suite...');

  // 1. Config file check
  const configPath = path.join(__dirname, '../firebase-applet-config.json');
  assert('firebase-applet-config.json exists', fs.existsSync(configPath));
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert('Config contains target Project ID "gen-lang-client-0628849129"', config.projectId === 'gen-lang-client-0628849129');
  assert('Config contains target database ID "ai-studio-vantavisionai-41676fcb-440e-4810-909c-de0f999fe055"',
    config.firestoreDatabaseId === 'ai-studio-vantavisionai-41676fcb-440e-4810-909c-de0f999fe055');

  // 2. Blueprint IR check
  const blueprintPath = path.join(__dirname, '../firebase-blueprint.json');
  assert('firebase-blueprint.json exists', fs.existsSync(blueprintPath));
  const blueprint = JSON.parse(fs.readFileSync(blueprintPath, 'utf8'));
  assert('Blueprint defines User, DetectionEvent, Incident, Policy, and AuditLog entities',
    blueprint.entities &&
    blueprint.entities.User &&
    blueprint.entities.DetectionEvent &&
    blueprint.entities.Incident &&
    blueprint.entities.Policy &&
    blueprint.entities.AuditLog
  );
  assert('Blueprint maps firestore collection paths',
    blueprint.firestore &&
    blueprint.firestore['/events/{eventId}'] &&
    blueprint.firestore['/incidents/{incidentId}']
  );

  // 3. Security rules check
  const rulesPath = path.join(__dirname, '../firestore.rules');
  assert('firestore.rules exists', fs.existsSync(rulesPath));
  const rules = fs.readFileSync(rulesPath, 'utf8');
  assert('Rules enforce rules_version 2', rules.includes("rules_version = '2'"));
  assert('Rules enforce global default-deny catch-all', rules.includes('match /{document=**} {\n      allow read, write: if false;\n    }'));
  assert('Rules include admin role check', rules.includes('isAdmin()'));
  assert('Rules enforce immutability on audit log', rules.includes('allow update, delete: if false;'));

  // 4. TypeScript services check
  const firebaseTsPath = path.join(__dirname, '../src/firebase.ts');
  assert('src/firebase.ts exists', fs.existsSync(firebaseTsPath));
  const firebaseTs = fs.readFileSync(firebaseTsPath, 'utf8');
  assert('src/firebase.ts initializes firestore with databaseId', firebaseTs.includes('firebaseConfig.firestoreDatabaseId'));
  assert('src/firebase.ts includes testConnection check', firebaseTs.includes('testConnection'));

  const firestoreTsPath = path.join(__dirname, '../src/services/firestore.ts');
  assert('src/services/firestore.ts exists', fs.existsSync(firestoreTsPath));
  const firestoreTs = fs.readFileSync(firestoreTsPath, 'utf8');
  assert('src/services/firestore.ts implements handleFirestoreError conforming to FirestoreErrorInfo',
    firestoreTs.includes('handleFirestoreError') &&
    firestoreTs.includes('OperationType')
  );

  const authTsPath = path.join(__dirname, '../src/services/auth.ts');
  assert('src/services/auth.ts exists', fs.existsSync(authTsPath));
  const authTs = fs.readFileSync(authTsPath, 'utf8');
  assert('src/services/auth.ts implements signInWithGoogle and signOutCurrentUser',
    authTs.includes('signInWithGoogle') &&
    authTs.includes('signOutCurrentUser')
  );

  // 5. Client integration check
  const clientJsPath = path.join(__dirname, '../static/firebase-client.js');
  assert('static/firebase-client.js exists', fs.existsSync(clientJsPath));
  const clientJs = fs.readFileSync(clientJsPath, 'utf8');
  assert('static/firebase-client.js exposes window.VantaFirebase API', clientJs.includes('window.VantaFirebase ='));

  const htmlPath = path.join(__dirname, '../static/index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');
  assert('index.html loads firebase-client.js module', html.includes('src="/static/firebase-client.js"'));
  assert('index.html includes auth button #btn-auth-action in topbar', html.includes('id="btn-auth-action"'));

  console.log(`[FIREBASE SUITE] Complete: ${passed}/${total} assertions passed.`);
  if (passed !== total) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSuite().catch(err => {
  console.error('[FIREBASE SUITE] Fatal error:', err);
  process.exit(1);
});
