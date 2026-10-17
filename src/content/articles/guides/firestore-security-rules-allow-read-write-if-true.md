---
title: "Firestore rules: why allow read, write: if true leaves your database public"
description: "What Firebase test mode and if true rules really allow, how to check whether your Firestore or Storage is open to the public, and the rules to deploy instead."
pubDate: 2026-10-16
category: guide
tags:
  - firebase
  - firestore
  - security-rules
  - firebase-storage
  - app-check
related:
  - firebase-security-rules-checklist
  - firebase-api-key-public-app-check
  - idor-broken-object-level-authorization-nextjs-supabase
faqs:
  - question: "Is allow read, write: if true ever safe in Firestore?"
    answer: "Not on a database a deployed app talks to. Firebase's own docs say never to use that ruleset in production because it lets anyone overwrite your entire database. Use it only in the local emulator, never on a real project."
  - question: "What happens when Firestore test mode expires after 30 days?"
    answer: "The test mode rule is open until a date written into the rule, then it denies every client request. Until that date anyone can read and write everything. After it, your app stops working. Replace it with real rules before you share the app, and do not just move the date forward."
  - question: "Is my Firestore database public if someone has my Firebase config?"
    answer: "Only if your rules allow it. The config, including the apiKey and projectId, is public by design and ships in your JavaScript. Firebase's insecure rules page says that with open rules, anyone who guesses your project ID can steal, modify, or delete the data. Strict rules are what stop them."
  - question: "Does App Check fix open Firestore rules?"
    answer: "No. App Check rejects requests that do not come from your registered app once you enforce it, but it does not decide which user may read which document. You still need rules that check request.auth."
---

AI builders love Firebase because the app works on the first try. That is often because the database was created in test mode, or because the agent wrote `allow read, write: if true;` when a query failed. Both mean anyone on the internet can read, change, or delete your data, not only people using your app.

Checked against the Firebase docs linked below on October 16, 2026.

To see what your live app exposes, run it through the [Live App Scanner](/live-scan/). It reads the Firebase config from your shipped JavaScript and tests, read only, whether your database answers without sign in.

## What if true and test mode actually do

Every request from the Firestore web or mobile SDK is checked against your Security Rules. Firebase's [get started guide](https://firebase.google.com/docs/firestore/security/get-started) shows this "allow all" ruleset with the warning that it should never be used in production, because it lets anyone overwrite your entire database:

```
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
```

`{document=**}` matches every document in every collection. `if true` means no condition at all. Signed in, signed out, your app, or a script: all allowed.

Test mode is the time limited version. When you create a database in the console you pick Locked mode or Test mode, and the [rules basics](https://firebase.google.com/docs/rules/basics) page says Test mode allows anyone access. The test mode template looks like this, with a date about 30 days out:

```
match /{document=**} {
  allow read, write: if request.time < timestamp.date(2026, 11, 15);
}
```

That gives two bad outcomes. Until the date, the database is wide open. After it, every client request is denied and the app breaks, which is when many builders paste `if true` to make it work again, or push the date forward. Neither is a fix.

## Why the public config makes this a real leak

Your `firebaseConfig`, with `apiKey`, `projectId`, and the rest, is meant to ship in the browser. That is normal, and our guide on [why the Firebase API key is public](/guides/firebase-api-key-public-app-check/) explains it. The catch is that the config is all a stranger needs to talk to your database. Firebase's [insecure rules page](https://firebase.google.com/docs/rules/insecure-rules) puts it plainly: if you are not authenticating users and configuring rules, anyone who guesses your project ID can steal, modify, or delete the data.

Hiding the config does not help. It is in your JavaScript bundle for anyone who opens the page. Moving keys around is useful for real secrets, which the [secrets guide](/guides/keep-secrets-out-of-frontend-code/) covers, but for Firestore the rules are the only lock. Open Firebase databases are a well known target for automated scanning, so assume an open one will be found.

## How to tell if yours is open

1. Open the Firebase console, go to **Firestore**, then the **Rules** tab. The console always shows the most recently deployed rules, so trust it over the `firestore.rules` file in your repo.
2. Search the rules for `if true`, a bare `allow read, write;`, and `request.time < timestamp.date`. Any of these on a broad path means open access.
3. Look for a leftover catch all. In Firestore, if more than one `allow` matches a request, access is granted if any condition is true. Firebase's [rules structure](https://firebase.google.com/docs/firestore/security/rules-structure) page shows a strict rule being overridden by a later `match /{document=**}` with `if true`. Tightening one collection does nothing while that catch all remains.
4. Click **Rules Playground**. Run a `get` on a real document path with Authentication turned off. If it says allowed on private data, you have a leak. Repeat as a signed in user with a different uid than the owner.
5. Do the same in **Storage**, under its own Rules tab. A Firestore rules file does not protect a bucket.
6. Check from the outside with the [Live App Scanner](/live-scan/), which tests your deployed app the way a stranger would.

## The rules to use instead

Start from deny. Firestore denies any request that no rule allows, so delete the catch all and add a `match` for each collection your app uses.

`allow read, write: if request.auth != null;` is a step up, but it only means "signed in". Firebase's insecure rules page warns that it gives every logged in user access, including accounts created a minute ago. For private data, compare the user to the owner. Letting any account open any record is the same bug as [IDOR in Supabase and Next.js apps](/guides/idor-broken-object-level-authorization-nextjs-supabase/).

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // One document per user, keyed by their uid
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }

    // Shared collection where each document stores its owner
    match /projects/{projectId} {
      allow read, delete: if request.auth != null
        && request.auth.uid == resource.data.ownerId;
      allow create: if request.auth != null
        && request.auth.uid == request.resource.data.ownerId;
      allow update: if request.auth != null
        && request.auth.uid == resource.data.ownerId
        && request.resource.data.ownerId == resource.data.ownerId;
    }
  }
}
```

`resource.data` is the document as stored. `request.resource.data` is the document after the write. The update rule stops a user from handing a document to someone else by changing `ownerId`. Your client queries must also filter on `ownerId`, because rules are not filters: a query that could return a document the user cannot read fails as a whole. The [Firebase security rules checklist](/checklists/firebase-security-rules-checklist/) covers that, field limits with `hasOnly`, and admin roles with custom claims.

## The same mistake in Firebase Storage

Storage has its own rules and the same trap. The insecure rules page shows this open version, noting it makes every file in the bucket readable and overwritable by anyone:

```
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write;
    }
  }
}
```

Keep files under a path that includes the user's uid and check it, with a size and type limit on uploads:

```
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{userId}/{fileName} {
      allow read, delete: if request.auth != null && request.auth.uid == userId;
      allow create, update: if request.auth != null
        && request.auth.uid == userId
        && request.resource.size < 5 * 1024 * 1024
        && request.resource.contentType.matches('image/.*');
    }
  }
}
```

If some files must be public, such as product images, give them a separate path with `allow read;` and keep writes owner only.

## Deploy the new rules

**In the console:** paste the rules into the Firestore Rules editor, test them in the Playground, then click **Publish**. Do the same in Storage.

**With the Firebase CLI:** keep `firestore.rules` and `storage.rules` in your repo, listed in `firebase.json`, and deploy them:

```
firebase deploy --only firestore:rules,storage
```

Pick one method and stick to it. Firebase's docs warn that a CLI deploy overwrites whatever is in the console, so a console fix can be silently undone by the next deploy of an old rules file. Firestore says rule changes can take up to a minute to affect new queries and up to 10 minutes to reach active listeners.

## Test rules before every deploy

The Playground is good for a quick check. For anything you will change again, add tests that run against the local emulator. The `@firebase/rules-unit-testing` library lets you act as a signed out user or as a specific uid, then assert that a read or write fails or succeeds with `assertFails` and `assertSucceeds`. Run the suite with:

```
firebase emulators:exec --only firestore "npm test"
```

Write at least three tests per private collection: signed out read fails, owner read succeeds, another user's read fails. If an AI agent edits your rules later, these tests catch it opening access to make a feature work. The [rules unit tests](https://firebase.google.com/docs/rules/unit-tests) page has the full API.

## App Check is the second layer

[App Check](https://firebase.google.com/docs/app-check) checks that requests come from your registered app. Once you click **Enforce** for Cloud Firestore or Cloud Storage in the console, unverified requests are rejected. Watch the metrics before enforcing so real users are not blocked. It makes scripted abuse harder, but it is not authentication, and anyone using your real app is still bound only by your rules.

## If yours is open right now

- [ ] Publish deny by default rules with owner checks for Firestore and for Storage, today
- [ ] Remove every `if true`, bare `allow read, write;`, and `request.time` test mode rule, including catch alls
- [ ] Confirm in the Playground that a signed out `get` on private data is denied
- [ ] Update `firestore.rules` and `storage.rules` in your repo so the next deploy does not undo the fix
- [ ] Look through your data for documents or files you did not create, and remove them
- [ ] If private user data could have been read, treat it as a possible data breach and check what you owe your users under the privacy laws that apply to you
- [ ] Scan your repo for real secrets, such as service account JSON, with the [GitHub leak check guide](/guides/check-if-api-key-leaked-on-github/)
- [ ] Turn on App Check enforcement once metrics look clean
- [ ] Re run the [Live App Scanner](/live-scan/) and review the other [common vibe coded app vulnerabilities](/guides/common-vibe-coded-app-vulnerabilities/)

## Sources

- [Firebase: Get started with Cloud Firestore Security Rules](https://firebase.google.com/docs/firestore/security/get-started)
- [Firebase: Avoid insecure rules](https://firebase.google.com/docs/rules/insecure-rules)
- [Firebase: Basic Security Rules (Locked mode and Test mode)](https://firebase.google.com/docs/rules/basics)
- [Firebase: Structuring Cloud Firestore Security Rules](https://firebase.google.com/docs/firestore/security/rules-structure)
- [Firebase: Writing conditions for Cloud Firestore Security Rules](https://firebase.google.com/docs/firestore/security/rules-conditions)
- [Firebase: Security Rules and Firebase Authentication](https://firebase.google.com/docs/rules/rules-and-auth)
- [Firebase: Get started with Security Rules for Cloud Storage](https://firebase.google.com/docs/storage/security/get-started)
- [Firebase: Manage and deploy Firebase Security Rules](https://firebase.google.com/docs/rules/manage-deploy)
- [Firebase: Test your Cloud Firestore Security Rules with the emulator](https://firebase.google.com/docs/firestore/security/test-rules-emulator)
- [Firebase: Build unit tests for Security Rules](https://firebase.google.com/docs/rules/unit-tests)
- [Firebase: Enable App Check enforcement](https://firebase.google.com/docs/app-check/enable-enforcement)
