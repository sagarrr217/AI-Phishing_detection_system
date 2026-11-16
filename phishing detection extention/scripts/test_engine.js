/**
 * PhishShield AI — Detector Engine Verification Test
 */

require('./ml-model-data.js');
const engine = require('./detector-engine.js');

const testCases = [
  {
    url: 'https://google.com',
    expectedStatus: 'safe',
    label: 'Legitimate Global Platform (Google)'
  },
  {
    url: 'https://www.paypal.com/signin',
    expectedStatus: 'safe',
    label: 'Legitimate Brand Domain (PayPal)'
  },
  {
    url: 'http://localhost:3000/',
    expectedStatus: 'safe',
    label: 'Localhost Development Environment'
  },
  {
    url: 'http://my-blog.org/post/1',
    expectedStatus: 'warning',
    label: 'Unencrypted HTTP Public Website'
  },
  {
    url: 'http://paypal-verification-update.tk/login',
    expectedStatus: 'danger',
    label: 'PayPal Brand Impersonation on .tk TLD'
  },
  {
    url: 'http://192.168.1.100/account/verify',
    expectedStatus: 'danger',
    label: 'Direct IP Host with verification path'
  },
  {
    url: 'http://appleid.apple.com.security-verify.xyz/account',
    expectedStatus: 'danger',
    label: 'Subdomain disguise attacking Apple ID'
  },
  {
    url: 'http://paypa1-secure-billing.com/signin',
    expectedStatus: 'danger',
    label: 'Homoglyph paypa1 spoof'
  }
];

console.log('========================================================================');
console.log('🧪 RUNNING PHISHSHIELD AI DETECTOR ENGINE DYNAMIC SCORE & ML TESTS');
console.log('========================================================================\n');

let passed = 0;
const scores = [];

testCases.forEach((tc, idx) => {
  const res = engine.analyzeURL(tc.url);
  const isMatch = res.status === tc.expectedStatus;
  if (isMatch) passed++;
  scores.push(res.safetyScore);

  console.log(`[${isMatch ? 'PASS ✓' : 'FAIL ✗'}] Test #${idx + 1}: ${tc.label}`);
  console.log(`    URL: ${tc.url}`);
  console.log(`    Status: ${res.status.toUpperCase()} | Safety Score: ${res.safetyScore}/100 | Threat: ${res.threatScore}/100`);
  console.log(`    AI Model: ${res.aiModel} | Confidence: ${res.aiConfidence} | Phish Prob: ${Math.round(res.aiPhishingProb * 100)}%`);
  console.log(`    TLD Display: ${res.metrics.tldLabel} | Protocol: ${res.metrics.protocolLabel}`);
  console.log(`    Findings: ${res.findings.map(f => f.title).join('; ') || 'None (Clean)'}`);
  console.log('');
});

// Verify dynamic variance: scores must not all be identical
const uniqueScores = new Set(scores);
console.log(`Unique Score Count across ${testCases.length} URLs: ${uniqueScores.size} distinct scores.`);
console.log(`Observed Scores: ${scores.join(', ')}`);

if (uniqueScores.size >= 4 && passed === testCases.length) {
  console.log('\n🎉 ALL TESTS PASSED! Scores change dynamically and accurately per site!\n');
} else {
  console.error('\n⚠️ Score variance check or status check failed.');
  process.exit(1);
}
