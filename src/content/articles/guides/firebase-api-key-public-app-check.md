---
title: "Is it safe to expose your Firebase API key?"
description: "Why the Firebase web API key is public by design, the one restriction that makes it dangerous, and how Security Rules and App Check actually protect your data."
pubDate: 2026-10-14
category: guide
tags:
  - firebase
  - api-keys
  - app-check
related:
  - keep-secrets-out-of-frontend-code
  - check-if-api-key-leaked-on-github
  - common-vibe-coded-app-vulnerabilities
faqs:
  - question: "Google emailed me about a publicly accessible API key. Is my Firebase project hacked?"
    answer: "Not necessarily. If the key in the email is your Firebase browser key and its API restrictions list only Firebase APIs, Firebase's docs say it is safe in client code. Check the restrictions in Google Cloud console under APIs and Services, Credentials, and remove anything that is not a Firebase API."
  - question: "Can I use my Firebase API key for Gemini or Maps?"
    answer: "Do not. Firebase's docs say to use Firebase keys only for Firebase services and to keep the Generative Language API off that key's allowlist. Create a separate, restricted key, and call paid APIs like Gemini from a server."
  - question: "Does App Check replace Security Rules?"
    answer: "No. Security Rules decide which users can read or write which data. App Check makes it harder for scripts and other apps to call your backend at all. You need both."
---

AI builders put the Firebase config object straight into frontend code, and scanners, AI reviewers, and Google itself sometimes flag the `apiKey` in it. Here is what that key does, when it is fine, and when it is a real problem.

Checked against the Firebase and Google Cloud docs linked below on October 14, 2026.

To see what your live app exposes, run it through the [Live App Scanner](/live-scan/). It reads your Firebase config from the shipped JavaScript and tests, read only, whether your database answers without sign in.

## The short answer

A Firebase API key **identifies** your project. It does not **authorize** anything. Firebase's own docs say keys restricted to Firebase services do not need to be treated as secrets and are safe in code and config files. Your data is protected by **Firebase Security Rules** and **App Check**, not by hiding the key.

That is why the [VibeLocked scanner](/scan/) reports an `AIza...` key as "review", not "secret". It is safe only when the conditions below hold.

## When the key becomes a real problem

Check the key in Google Cloud console under **APIs and Services, Credentials**. It is safe to ship when:

1. It is the key auto created by Firebase (named like "Browser key (auto created by Firebase)").
2. Its **API restrictions** list only Firebase related APIs.
3. The list does **not** include other paid APIs. Firebase's docs single out the **Generative Language API** (Gemini). If that API is on your public key, anyone who copies the key can run Gemini on your bill.

If your app needs Maps, Gemini, or another Google API, create a **separate key** for it with its own restrictions (HTTP referrer for browser keys, or keep it server side). AI tools often reuse the Firebase key for everything. Undo that.

## What actually protects your data: Security Rules

If your Firestore, Realtime Database, or Storage rules are open, the key does not matter. Anyone can read your data with or without it. Rules like these are the real leak:

```
allow read, write: if true;
```

Lock rules to the signed in user, for example:

```
match /users/{userId}/{document=**} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
```

Run the full [Firebase security rules checklist](/checklists/firebase-security-rules-checklist/) before launch, including the test mode rules that expire after 30 days.

## What protects your backend from abuse: App Check

App Check attests that a request comes from your real app on a real device or browser. When you **enforce** it, requests without a valid App Check token are rejected. It supports Cloud Firestore, Realtime Database, Cloud Storage, Cloud Functions (callable), Firebase AI Logic, and more.

For a web app:

1. In the Firebase console, open **App Check** and register your web app with reCAPTCHA Enterprise (or reCAPTCHA v3).
2. Initialize App Check in your client before other Firebase calls:

```js
import { initializeApp } from 'firebase/app';
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from 'firebase/app-check';

const app = initializeApp(firebaseConfig);
initializeAppCheck(app, {
  provider: new ReCaptchaEnterpriseProvider('YOUR_SITE_KEY'),
  isTokenAutoRefreshEnabled: true,
});
```

3. Watch the App Check metrics for a few days to confirm real traffic carries tokens.
4. Turn on **enforcement** per product. Before enforcement, App Check only measures.

If you run your own backend, send the App Check token with each request and verify it on the server with the Admin SDK (`getAppCheck().verifyToken(token)`).

App Check raises the cost of abuse. It is not authentication. Keep Security Rules strict either way.

## Five minute check

- [ ] Firebase key restricted to Firebase APIs only, no Generative Language API
- [ ] Separate, restricted keys for Maps or Gemini, with Gemini called from a server
- [ ] No `if true` rules in Firestore, Realtime Database, or Storage
- [ ] App Check registered and enforced for the products you use
- [ ] Repo scanned with [/scan](/scan/) for service account JSON (`-----BEGIN PRIVATE KEY-----`), which is a real secret

## Sources

- [Firebase: Learn about and manage API keys](https://firebase.google.com/docs/projects/api-keys)
- [Firebase App Check](https://firebase.google.com/docs/app-check)
- [Firebase: Verify App Check tokens from a custom backend](https://firebase.google.com/docs/app-check/custom-resource-backend)
- [Firebase Security Rules](https://firebase.google.com/docs/rules)
