# Third-Party Notices

## Certificate favicon — Icons8

The project uses the user-supplied transparent certificate icon at:

```text
public/assets/images/favicon/certificate-96x96.png
```

The original supplied filename was `icons8-certificate-96.png`, identifying Icons8 as the source. The public application therefore includes the footer attribution:

```text
Certificate icon by Icons8 ↗
```

linking to:

https://icons8.com

Icons8's current licensing information should be checked before public redistribution or before removing attribution:

https://icons8.com/license

The project intentionally keeps attribution in the public build. If the repository owner holds a licence that permits use without attribution, the footer may be adjusted only in accordance with that licence.

No font files or other Icons8 asset packs are distributed by this repository.

## NIST PKITS standards corpus (test-only)

The standards-hardening workflow can download a pinned copy of the NIST PKITS certificate-policy vectors from the Go project's testdata mirror. The corpus is used only during development/CI and is **not** bundled into `public/` or the released browser runtime.

Pinned Go source revision:

```text
67c1d421161d3d1ae9f5fd005e84c29fd0d9f896
```

Upstream mirror path: `src/crypto/x509/testdata/nist-pkits/`.
