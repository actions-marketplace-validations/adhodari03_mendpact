# Project website

The project website lives in `site/` and is prepared for GitHub Pages at
`https://adhodari03.github.io/mendpact/`. A repository project site uses this path; no separate
repository named `github.io` or custom domain is required.

The website describes capabilities available in source, links to the repository documentation,
labels the contract-change demonstration as illustrative, and explains the offline static-evidence
workflow. It does not scan endpoints or call model providers. OpenAI's single recorded live
integration check is distinguished from Anthropic and Gemini's mocked tests. Hosted services
remain labelled as planned.

## Files

- `site/index.html`: content, navigation, examples, and accessible document structure.
- `site/styles.css`: responsive layout, colors, typography, and reduced-motion support.
- `site/app.js`: illustrative change selector and scoped command-copy buttons.
- `site/assets/mark.svg`: local vector brand mark and favicon.
- `site/.nojekyll`: keeps the published directory as static assets.
- `scripts/check_site.py`: validates the publishable file set, links, anchors, image alt text,
  duplicate attributes, and explicit button types.
- `.github/workflows/pages.yml`: validates pull requests and publishes only from `main`.

There are no frontend dependencies, build step, analytics, external fonts, or credentials. Only
`site/` is uploaded, so repository reports and local configuration are outside the publishing
directory. Update the validator's file set when deliberately adding an asset.

## Local preview

From the repository root:

```bash
python3 scripts/check_site.py
node --check site/app.js
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

Open `http://127.0.0.1:8080/`. Check desktop and narrow layouts, keyboard navigation, all three
demo choices, the evidence workflow, and both copy buttons. Press Ctrl+C to stop the preview
server.

## Enable GitHub Pages

1. Commit and push the website feature branch. Open a pull request into `main`.
2. In the repository, open **Settings → Pages → Build and deployment** and choose **GitHub
   Actions** as the source.
3. Merge after the **Project website / validate** and other required checks pass.
4. Open **Actions → Project website** and wait for the deployment to finish. If Pages was enabled
   after the merge, run this workflow manually on `main`.
5. Visit `https://adhodari03.github.io/mendpact/`. Optionally add that URL to the repository's
   **About → Website** field.

The `github-pages` environment should permit deployments from `main`. Pull request jobs only
validate files; they do not publish. The website does not require a package release or a new
version tag. These files configure deployment; a local preview does not confirm live publication.

GitHub documents this setup in [Using custom workflows with GitHub
Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

## Keep the claims current

Check the CLI, Action metadata, `docs/ROADMAP.md`, and `docs/VALIDATION.md` before changing feature
or validation claims. Do not turn mocked checks into claims of live API validation. Link to
released versions only after verifying that those versions contain the documented features.
