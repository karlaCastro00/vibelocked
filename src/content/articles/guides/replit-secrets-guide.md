---
title: "Replit Secrets guide"
description: "How to store API keys in Replit Secrets, read them safely in code, and avoid leaking them through public Repls, frontends, and logs."
pubDate: 2026-10-13
category: guide
tags:
  - replit
  - secrets
related:
  - keep-secrets-out-of-frontend-code
  - check-if-api-key-leaked-on-github
  - first-hour-after-an-api-key-leaks
faqs:
  - question: "Where should I put API keys in Replit?"
    answer: "In the Secrets tool. Replit stores them encrypted and exposes them to your app as environment variables, so they are not written into your source files."
  - question: "Are Replit Secrets visible if someone remixes my app?"
    answer: "Replit's docs say secret values are not copied when someone remixes your app, though secret names may be visible. Check the current Replit docs for your app's visibility settings."
  - question: "Can I use a Replit Secret in frontend JavaScript?"
    answer: "Only if you are fine with it being public. Anything sent to the browser can be read by users. Keep private keys on the server side of your app and call the third party API from there."
---

Replit makes it easy to paste a key straight into `main.py` or `index.js`. Don't. Use Secrets, and keep them on the server side of your app.

Checked against the Replit docs linked below on October 13, 2026.

## Add a secret

1. Open your App and find the **Secrets** tool (search for it in the tools panel).
2. Add a key such as `OPENAI_API_KEY` and paste the value.
3. Restart the app so the new value is loaded.

## Read it in code

```python
import os
api_key = os.environ["OPENAI_API_KEY"]
```

```js
const apiKey = process.env.OPENAI_API_KEY;
```

Failing loudly when a secret is missing (as `os.environ[...]` does) is better than silently sending requests with an empty key.

## Ways secrets still leak on Replit

- **Hardcoding during a quick test.** If a key was ever in a file, assume it is in history and rotate it.
- **Sending it to the browser.** If your app has a frontend, never inject a private key into HTML or client JavaScript. Make a server route that calls the API.
- **Logging it.** `print(os.environ)` or logging request headers can write secrets to logs you share in screenshots or support threads.
- **Agent generated code.** Ask Replit Agent or any AI tool to read keys from environment variables, then check its output for literal key strings.
- **Deployment config.** Make sure your deployment has the secrets it needs, and that you are not passing them in a public URL or query string.

## If a key leaked

Revoke or rotate it at the provider, update the value in Secrets, and restart. Then follow [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/).

## Official docs

- [Replit Secrets](https://docs.replit.com/core-concepts/project-editor/app-setup/secrets)
- [Replit deployment secrets](https://docs.replit.com/cloud-services/deployments/about-deployments)
