# 发布到 GitHub 与在线演示

## 1. 推送到 GitHub

在 GitHub 网页上新建一个**空仓库**（例如 `stellar-lanes`），不要勾选添加 README、.gitignore 或 License（本地已经有了）。然后在本地：

```bash
cd ~/project/stellar-lanes
git remote add origin https://github.com/silchenn/stellar-lanes.git
git push -u origin main
```

## 2. 开启 GitHub Pages（在线体验）

仓库里已经带了自动部署配置 `.github/workflows/pages.yml`，它会把 `frontend/` 目录发布成网页。

1. 打开仓库页面 → **Settings** → 左侧 **Pages**。
2. **Build and deployment → Source** 选择 **GitHub Actions**。
3. 到 **Actions** 标签页，找到 "Deploy demo to GitHub Pages"：
   - 如果还没运行，点 **Run workflow** 手动触发一次；
   - 之后每次推送修改 `frontend/` 都会自动重新部署。
4. 运行成功后，演示地址是：

   ```
   https://silchenn.github.io/stellar-lanes/
   ```

5. README 的「在线体验」链接已经指向这个地址；再把它填到仓库首页右侧 **About → Website**。

> 免费账户的 GitHub Pages 只支持**公开仓库**。

## 3. 让仓库首页更好看（可选）

- **About** 里写一句简介，并添加 Topics：`network-security`、`ids`、`threejs`、`visualization`、`mitre-attack`。
- 把演示动图放到 `docs/assets/demo.gif`，替换 README 顶部的 TODO 注释。
