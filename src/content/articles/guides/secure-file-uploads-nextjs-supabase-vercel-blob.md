---
title: "Secure file uploads in Next.js (Supabase Storage and Vercel Blob)"
description: "Stop vibe-coded avatar and document uploads from trusting file.type, skipping auth, or dumping files into public/. Direct-to-storage uploads, MIME allow-lists, filename sanitizing, and private buckets with signed URLs."
pubDate: 2026-10-15
category: guide
tags:
  - nextjs
  - supabase
  - vercel
  - uploads
  - storage
related:
  - supabase-storage-bucket-security
  - ship-checklist-for-a-vibe-coded-app
  - common-vibe-coded-app-vulnerabilities
  - lovable-bolt-pre-launch-security-checklist
  - keep-secrets-out-of-frontend-code
  - csp-content-security-policy-vibe-coded-apps
faqs:
  - question: "Is checking file.type or the file extension enough?"
    answer: "No. The browser Content-Type and the client filename are attacker-controlled. Allow-list MIME types on the server, enforce a max size, and prefer magic-byte checks or image re-encoding for avatars. Treat Content-Type as a hint, not proof."
  - question: "Should uploads go through a Next.js Route Handler or Server Action?"
    answer: "Tiny files can. Anything bigger than a few megabytes should go direct to storage with a short-lived token. Vercel Functions cap request and response bodies at 4.5 MB. Next.js Server Actions default to a 1 MB body limit. Client uploads to Vercel Blob or Supabase Storage avoid those ceilings."
  - question: "Can I make the whole Supabase bucket or Vercel Blob store public for convenience?"
    answer: "Only for assets you would post publicly (marketing images, maybe public avatars). Private user docs, invoices, and IDs belong in a private bucket or private Blob, served with short-lived signed URLs. Public convenience is how private files leak."
  - question: "Where do filename path traversal bugs show up?"
    answer: "Anywhere you write the client filename to disk or into an object key without sanitizing. Use path.basename, drop path separators, add a random suffix, and scope keys under the authenticated user id. Never write user uploads into a publicly served static folder without validation."
  - question: "How does this relate to Supabase Storage RLS?"
    answer: "This guide covers the upload path and validation. Bucket privacy and storage.objects policies still matter. See the Supabase Storage bucket security guide for RLS patterns and signed URL access control."
---

AI builders love avatar pickers and "upload your PDF" forms. The usual vibe-coded shape is a Route Handler that reads `FormData`, trusts `file.type`, and writes `file.name` somewhere public. That pattern fails the [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html): Content-Type is spoofable, extensions are bypassable, and files must not land under a web-served root without controls.

This guide focuses on the **upload path** in Next.js apps using Supabase Storage or Vercel Blob: auth before permission, allow-lists, safe object keys, and private-by-default storage. For Supabase bucket privacy and `storage.objects` RLS, use [Supabase Storage bucket security](/guides/supabase-storage-bucket-security/).

Checked against the Next.js, Vercel, Supabase, and OWASP docs linked below on October 15, 2026.

## Why vibe-coded upload routes are unsafe

A typical generated handler:

```ts
// app/api/upload/route.ts  (do not ship this)
export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get('file') as File;
  // trusts the browser
  if (!file.type.startsWith('image/')) {
    return Response.json({ error: 'not an image' }, { status: 400 });
  }
  // path traversal + predictable names
  await writeFile(`public/uploads/${file.name}`, Buffer.from(await file.arrayBuffer()));
  return Response.json({ url: `/uploads/${file.name}` });
}
```

Problems stacked on top of each other:

1. **Trusts `file.type` / extension.** The client sets Content-Type. OWASP says do not trust it; allow-list types and validate content.
2. **No auth.** Anyone who finds `/api/upload` can fill your storage or host malware on your domain. Same class of bug as [missing auth on public routes](/guides/common-vibe-coded-app-vulnerabilities/).
3. **No size cap.** Large uploads burn bandwidth, fill buckets, and can DoS parsers.
4. **Writes under `public/`.** Anything there is served as a static asset. HTML or SVG uploads become XSS hosts.
5. **Raw client path as the key.** `../../.env` style names, double extensions, and collisions are classic unrestricted-upload issues.
6. **Public bucket "so the img tag works".** Convenient for demos, wrong for private docs.

## Prefer direct-to-storage for anything bigger than tiny files

Routing every byte through your Next.js server hits two separate ceilings (verified today):

| Limit | Verified value | Source |
| --- | --- | --- |
| Next.js Server Actions body | **1 MB default** (raise with `serverActions.bodySizeLimit`) | [Next.js `serverActions` config](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions) |
| Vercel Function request/response body | **4.5 MB** (oversize returns 413 `FUNCTION_PAYLOAD_TOO_LARGE`) | [Vercel Functions limitations](https://vercel.com/docs/functions/limitations) |

Vercel Blob's client-upload docs state that for files **larger than 4.5 MB**, the browser should upload **directly to Blob** after a token exchange with your server. Supabase documents standard (multipart) uploads as ideal for small files **not larger than 6 MB**, and recommends resumable (TUS) uploads above that.

High-level pattern:

1. Browser asks your authenticated API for permission (token or signed upload URL).
2. Browser uploads **to the storage provider**, not through your function body.
3. Your server records the resulting path/URL only after auth and validation rules you set.

Tiny avatars under about 1 MB can still use a Route Handler or Server Action with `request.formData()` ([Next.js Route Handlers](https://nextjs.org/docs/app/api-reference/file-conventions/route)). Do not raise body limits just to avoid learning client uploads.

## Auth before any upload permission

Never mint a Blob client token or a Supabase signed upload path for an anonymous caller.

**Vercel Blob:** In `onBeforeGenerateToken`, check the session and throw if missing. Vercel's client-upload guide says that without this check, anyone can upload to your store. Scope the pathname to the user id, and pass `userId` in `tokenPayload` for `onUploadCompleted`.

```ts
// app/api/avatar/upload/route.ts (shape only; wire your real auth)
import { handleUpload, type HandleUploadBody } from '@vercel/blob/client';
import { NextResponse } from 'next/server';
import { auth } from '@/lib/auth'; // your session helper

export async function POST(request: Request) {
  const body = (await request.json()) as HandleUploadBody;

  try {
    const jsonResponse = await handleUpload({
      body,
      request,
      onBeforeGenerateToken: async (pathname) => {
        const session = await auth();
        if (!session?.user?.id) {
          throw new Error('Not authenticated');
        }

        // Optional: require pathname to start with avatars/YOUR_USER_ID/
        const prefix = `avatars/${session.user.id}/`;
        if (!pathname.startsWith(prefix)) {
          throw new Error('Invalid upload path');
        }

        return {
          allowedContentTypes: ['image/jpeg', 'image/png', 'image/webp'],
          maximumSizeInBytes: 2 * 1024 * 1024, // 2 MB example
          addRandomSuffix: true,
          tokenPayload: JSON.stringify({ userId: session.user.id }),
        };
      },
      onUploadCompleted: async ({ blob, tokenPayload }) => {
        const { userId } = JSON.parse(tokenPayload || '{}');
        // Persist blob.url for userId in your DB (server only)
        void blob;
        void userId;
      },
    });

    return NextResponse.json(jsonResponse);
  } catch (error) {
    return NextResponse.json(
      { error: (error as Error).message },
      { status: 400 },
    );
  }
}
```

`allowedContentTypes` and `maximumSizeInBytes` are enforced with the client token (see the [Blob SDK `handleUpload` reference](https://vercel.com/docs/vercel-blob/using-blob-sdk)). Keep `BLOB_READ_WRITE_TOKEN` on the server only ([keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code/)).

**Supabase Storage:** Build the object key from `auth.getUser()` / `auth.uid()`, never from a form field claiming `userId`. Pair that with owner-scoped RLS on `storage.objects` ([bucket security guide](/guides/supabase-storage-bucket-security/)).

```ts
const {
  data: { user },
} = await supabase.auth.getUser();
if (!user) {
  return Response.json({ error: 'Unauthorized' }, { status: 401 });
}

const objectPath = `${user.id}/${safeName}`; // not formData.get('userId')
await supabase.storage.from('avatars').upload(objectPath, file, {
  contentType: 'image/png', // set after you validate; placeholder type
  upsert: false,
});
```

## Allow-list MIME types and max size on the server

Rules that hold for both providers:

- Maintain an **allow-list** (`image/jpeg`, `image/png`, `image/webp`, maybe `application/pdf`). Reject everything else.
- Enforce **max bytes** on the server (and again in Blob token options / Supabase bucket settings).
- Treat browser `Content-Type` and `file.type` as **untrusted hints**.
- For images, prefer a cheap **magic-byte check** or re-encode when practical.

Placeholder magic-byte sketch (not a full detector library):

```ts
const ALLOWED = new Set(['image/jpeg', 'image/png', 'image/webp']);
const MAX_BYTES = 2 * 1024 * 1024;

function sniffImageMime(bytes: Uint8Array): string | null {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return 'image/jpeg';
  }
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  ) {
    return 'image/png';
  }
  // WebP: RIFF....WEBP
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return 'image/webp';
  }
  return null;
}

async function assertSafeImage(file: File) {
  if (file.size > MAX_BYTES) {
    throw new Error('File too large');
  }
  const buf = new Uint8Array(await file.arrayBuffer());
  const sniffed = sniffImageMime(buf);
  if (!sniffed || !ALLOWED.has(sniffed)) {
    throw new Error('Unsupported image type');
  }
  // Optional: decode and re-encode with a trusted image library, then store that buffer
  return sniffed;
}
```

Also set bucket-level MIME and size limits in the Supabase dashboard so a buggy client cannot bypass your Route Handler alone.

## Sanitize filenames and never dump into static `public/`

OWASP recommends generating a new filename (UUID-style) rather than trusting the client name.

```ts
import path from 'node:path';
import { randomBytes } from 'node:crypto';

function safeObjectKey(userId: string, originalName: string, ext: string) {
  const base = path.basename(originalName); // strips directories
  const cleaned = base.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
  const suffix = randomBytes(8).toString('hex');
  return `${userId}/${suffix}-${cleaned || 'upload'}.${ext}`;
}

// Example: safeObjectKey('YOUR_USER_ID', '../../../etc/passwd.png', 'png')
```

Never write uploads into `public/`, `static/`, or any folder your host serves as-is, unless you have validated type, size, and filename, and you accept that the file is world-readable. Prefer object storage outside the web root.

## Private by default; serve with short-lived signed URLs

**Supabase:** Keep user documents in a **private** bucket. Serve with `createSignedUrl` and a short expiry (minutes, not days) after the caller passes your `SELECT` policy. Public buckets are for content you would publish. Details and RLS examples: [Supabase Storage bucket security](/guides/supabase-storage-bucket-security/). Serving docs: [Supabase downloads / signed URLs](https://supabase.com/docs/guides/storage/serving/downloads).

**Vercel Blob:** Create the store as **private** when user content is involved. Client uploads can set `access: 'private'`. Serve through your authenticated Route Handler (Blob `get()`) or short-lived signed URLs, not by flipping the whole store to public so an `<img>` tag works without auth.

If you display avatars from Blob or Supabase on pages with a CSP, add those hosts to `img-src` deliberately ([CSP for vibe-coded apps](/guides/csp-content-security-policy-vibe-coded-apps/)). Do not open `img-src *` to "fix uploads."

## Self-test checklist

- [ ] Upload route or token handler requires a real session (logged-out request gets 401/400)
- [ ] Object keys are scoped to the authenticated user id (not a body `userId`)
- [ ] MIME allow-list enforced server-side; `file.type` alone is not enough
- [ ] Max size enforced (app code and provider/bucket settings)
- [ ] Filenames sanitized (`path.basename` + random suffix); no raw client paths
- [ ] No writes into `public/` / static web root for untrusted uploads
- [ ] Bucket / Blob store is private for user docs; public only for truly public assets
- [ ] Private files are fetched via signed URL or authenticated proxy, not a permanent public URL
- [ ] Large files use client/direct upload (respect 4.5 MB Vercel body limit and 1 MB Server Action default)
- [ ] `BLOB_READ_WRITE_TOKEN` / service role keys are server-only
- [ ] Supabase `storage.objects` RLS reviewed ([bucket guide](/guides/supabase-storage-bucket-security/))
- [ ] Folded into your [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app/) and [Lovable/Bolt pre-launch checklist](/checklists/lovable-bolt-pre-launch-security-checklist/)

## Sources

- [OWASP: File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Next.js: Route Handlers](https://nextjs.org/docs/app/api-reference/file-conventions/route)
- [Next.js: `serverActions` / `bodySizeLimit`](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions)
- [Vercel: Functions limitations (4.5 MB body)](https://vercel.com/docs/functions/limitations)
- [Vercel Blob: Client uploads](https://vercel.com/docs/vercel-blob/client-upload)
- [Vercel Blob: JS SDK (`handleUpload`, `allowedContentTypes`, `maximumSizeInBytes`)](https://vercel.com/docs/vercel-blob/using-blob-sdk)
- [Supabase: Storage](https://supabase.com/docs/guides/storage)
- [Supabase: Standard uploads](https://supabase.com/docs/guides/storage/uploads/standard-uploads)
- [Supabase: Serving assets / signed URLs](https://supabase.com/docs/guides/storage/serving/downloads)
