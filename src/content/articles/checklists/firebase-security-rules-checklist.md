---
title: "Firebase security rules checklist"
description: "Replace test mode, stop open rules, and check ownership, queries, and custom claims before you ship Firestore."
pubDate: 2026-10-07
category: checklist
tags:
  - firebase
  - firestore
  - security-rules
related:
  - supabase-rls-security-checklist
  - common-vibe-coded-app-vulnerabilities
  - keep-secrets-out-of-frontend-code
faqs:
  - question: "Is the Firebase apiKey in the client config a secret?"
    answer: "No. Google's API keys page says Firebase Security Rules and App Check protect Firestore, Realtime Database, and Cloud Storage data, not secrecy of the client API key. A service account JSON file is a secret."
  - question: "Does request.auth != null make a collection private?"
    answer: "No. It allows every signed-in user. Private user data also needs a check that request.auth.uid matches the owner on that document."
  - question: "Do security rules apply to the Admin SDK?"
    answer: "No. Firebase says the server client libraries bypass Cloud Firestore Security Rules and authenticate with Google Application Default Credentials. Authorization for that path belongs in your server code and in IAM."
---

Firebase will happily serve your database to the browser. The thing that stops a stranger is Security Rules, not the `apiKey` in `firebaseConfig`. This checklist is the pass to run on Firestore, and the same habits apply to Realtime Database and Cloud Storage, which have their own rules.

Checked against the Firebase docs linked below on October 14, 2026.

## Read the rules that are actually deployed

When you create a database or storage bucket in the console, Firebase asks you to choose Locked mode or Test mode. The [rules basics](https://firebase.google.com/docs/rules/basics) page says Locked mode denies access to all users for Cloud Firestore and Realtime Database. For Cloud Storage, Locked mode allows only authenticated users. Test mode allows anyone access.

Open the rules you deployed. Do not trust a memory of which button you clicked.

Locked mode for Firestore looks like this:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

If your rules contain `allow read, write: if request.time < timestamp.date(...)`, that condition is open until the timestamp and closed after it. Anyone can read and write until that date. Replace it before you share the app. Do not extend the date and call it a launch plan.

`rules_version = '2'` matters if you use recursive wildcards or collection group queries. The [get started guide](https://firebase.google.com/docs/firestore/security/get-started) says version 2 is required for those.

## The client config is not the lock

Google's [API keys](https://firebase.google.com/docs/projects/api-keys) page says security of Realtime Database, Cloud Firestore, and Cloud Storage is enforced with Firebase Security Rules and App Check, not by keeping the Firebase API key secret. It is normal for `apiKey`, `authDomain`, and `projectId` to be in the app.

The same page says not to rely only on restricting or hiding API keys. Restricting a key in Google Cloud is a useful extra limit. It does not replace rules.

What is a secret:

- A service account JSON file, or any Admin SDK credential.
- Cloud Functions environment variables that hold third-party API keys.

The get started guide says the server client libraries bypass all Cloud Firestore Security Rules and authenticate with Google Application Default Credentials. If you use the Admin SDK, the REST API, or the RPC API, set up IAM, and check the caller in your own code. Rules will not do it.

[App Check](https://firebase.google.com/docs/app-check) attests that a request comes from your app. It does not decide which user may read which document. Use it in addition to rules, not instead of them.

## Close the open patterns

Firebase's [insecure rules](https://firebase.google.com/docs/firestore/security/insecure-rules) page is the list to read. These are the patterns to search for in your rules file:

| Pattern | What it actually allows |
| --- | --- |
| `allow read, write: if true` | Anyone, signed in or not. |
| `allow read, write: if request.auth != null` | Every signed-in user, including accounts they just created. |
| A rule that checks auth but not the document owner | Any account can open any id it can guess or list. |

`request.auth != null` is a start for "you must be signed in." It is not a privacy rule. For a user-owned document, compare the uid. `resource.data` is the document already stored. `request.resource.data` is the document as it will exist after the write. `resource` is not available on create.

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow create: if request.auth != null
        && request.auth.uid == userId
        && request.resource.data.keys().hasOnly(['displayName', 'createdAt']);
      allow update: if request.auth != null
        && request.auth.uid == userId
        && request.resource.data.keys().hasOnly(['displayName', 'createdAt']);
      allow delete: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

`hasOnly` is how you stop a client from writing `admin: true` onto their own document. List the fields your app really writes. If the product needs more fields, add them on purpose.

Split `read` into `get` and `list`, and `write` into `create`, `update`, and `delete`, when those operations should differ. `allow read` covers both get and list. A list rule that is too wide dumps the collection.

## Rules are not filters

This is the mistake that makes a query fail, and then tempts you to open the rules.

Firestore does not run the query and then hide the documents the user cannot see. If the query could return a document the rules deny, the whole query fails. The [rules conditions](https://firebase.google.com/docs/firestore/security/rules-conditions) guide states this directly.

If the rule is `resource.data.visibility == 'public'`, the query has to constrain `visibility` to `public`. If the rule is `resource.data.owner == request.auth.uid`, the query has to constrain `owner` to the signed-in uid. A generated client that calls `getDocs(collection(db, 'orders'))` will fail closed, which is good, or someone will "fix" it by deleting the owner check, which is not.

Collection group queries need a rule written for the collection group. A rule on one path does not automatically cover every subcollection with the same id. See [securely query data](https://firebase.google.com/docs/firestore/security/rules-query).

## Roles belong in custom claims, not in a field the user can edit

You can store a role on a user document and read it with `get()` in rules. That works only if the user cannot write that field. If your update rule lets the owner change every field, they can set `role` to `admin`.

Firebase custom claims are set with the Admin SDK and show up on `request.auth.token`. The [custom claims](https://firebase.google.com/docs/auth/admin/custom-claims) page says to use them for access control, not as a profile store. The payload must stay within 1000 bytes. The client cannot set its own claims.

```
allow write: if request.auth.token.admin == true;
```

Check that claim in rules for admin writes. Still do not use `allow read: if true` on private collections just because writes are limited. Admin-only writes with public reads publish the data.

The [rules and auth](https://firebase.google.com/docs/rules/rules-and-auth) page shows the same `request.auth.token` check for Firestore, Realtime Database, and Storage. The syntax is different for each product. A Firestore rules file does not protect a Realtime Database or a Storage bucket. Open each rules editor.

## Test the rule, not the happy path in the UI

The UI hides requests that fail. Rules do not.

- Use the [Rules Playground](https://firebase.google.com/docs/rules/simulator). Run an unauthenticated read, a read as the owner, a read as a different uid, a create that sets `userId` to someone else, and an update that adds a field you did not allow.
- Add unit tests with the emulator. Firebase documents this in [unit tests for rules](https://firebase.google.com/docs/rules/unit-tests).
- Deploy rules before you share the hosting URL. A local emulator ruleset is not the production ruleset until you deploy it.

Firebase also publishes a short prompt on the Firestore get started page for asking a coding agent to write rules. Pair it with the [review prompt](/guides/security-review-prompt-for-ai-coding-tools) on this site, then read the rules file yourself. An agent that "makes the app work" will sometimes do that by opening access.

## A pass you can run in order

1. Open the deployed rules for Firestore, Realtime Database, and Storage.
2. Replace any `if true` and any timestamp test-mode rule.
3. For private data, require `request.auth.uid` to match the owner on read and on write.
4. Limit writable fields with `request.resource.data`.
5. Make sure client queries include the same constraints as the rules.
6. Confirm admin paths use custom claims or a server you control, not a client field.
7. Confirm the Admin SDK is not imported into client code. See the [secrets guide](/guides/keep-secrets-out-of-frontend-code).
8. Run the playground as two different users.
9. Deploy the rules you just tested.

If you also have a Supabase project in the same app, the matching pass is the [RLS checklist](/checklists/supabase-rls-security-checklist). The failure mode is the same: the client key is public, and the rules are the product.

## Official docs

- [Security rules basics](https://firebase.google.com/docs/rules/basics)
- [Firestore get started](https://firebase.google.com/docs/firestore/security/get-started)
- [Fix insecure rules](https://firebase.google.com/docs/firestore/security/insecure-rules)
- [Rules conditions](https://firebase.google.com/docs/firestore/security/rules-conditions)
- [Securely query data](https://firebase.google.com/docs/firestore/security/rules-query)
- [Rules and Firebase Authentication](https://firebase.google.com/docs/rules/rules-and-auth)
- [Custom claims](https://firebase.google.com/docs/auth/admin/custom-claims)
- [Rules Playground](https://firebase.google.com/docs/rules/simulator)
- [Rules unit tests](https://firebase.google.com/docs/rules/unit-tests)
- [API keys](https://firebase.google.com/docs/projects/api-keys)
- [App Check](https://firebase.google.com/docs/app-check)
