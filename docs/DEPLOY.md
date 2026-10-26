# Publishing to GitHub and the online demo

## 1. Push to GitHub

Create an **empty repository** on GitHub (here, `vela`). Don't add a README, .gitignore or license; they already exist locally. Then, locally:

```bash
cd ~/project/vela
git remote add origin https://github.com/silchenn/vela.git
git push -u origin main
```

## 2. Enable GitHub Pages (online demo)

The repository already includes a deployment workflow, `.github/workflows/pages.yml`, which publishes the `frontend/` directory as a website.

1. Open the repository → **Settings** → **Pages** in the sidebar.
2. Under **Build and deployment → Source**, choose **GitHub Actions**.
3. Go to the **Actions** tab and find "Deploy demo to GitHub Pages":
   - if it hasn't run yet, click **Run workflow** to trigger it once;
   - after that, every push that changes `frontend/` redeploys automatically.
4. Once it succeeds, the demo is at:

   ```
   https://silchenn.github.io/vela/
   ```

5. The README's "Live demo" link already points there; also add it under **About → Website** on the repository home page.

> On free accounts, GitHub Pages only works for **public repositories**.
>
> The online demo is an HTTPS page, so browsers won't let it connect to a LAN `ws://` backend. Live mode only works with pages opened locally.

## 3. Polish the repository page (optional)

- Write a one-line description under **About** and add topics: `network-security`, `ids`, `threejs`, `visualization`, `mitre-attack`.
- Put a demo GIF at `docs/assets/demo.gif` and replace the TODO comment at the top of the README.
