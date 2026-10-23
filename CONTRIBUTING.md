# How to Contribute

We'd love to accept your patches and contributions to this project. There are just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License Agreement (CLA). You (or your employer) retain the copyright to your contribution; this simply gives us permission to use and redistribute your contributions as part of the project. Head over to <https://cla.developers.google.com/> to see your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one (even if it was for a different project), you probably don't need to do it again.

## Code Reviews

All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose. Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more information on using pull requests.

### Submitting a Patch

1. Fork the repository and create a new feature branch from `main`.
2. Ensure all new `.go` and `.ts` source files include the standard Apache 2.0 license header:
   ```bash
   go install github.com/google/addlicense@latest
   $(go env GOPATH)/bin/addlicense -c "Google LLC" -l apache -ignore "web/node_modules/**" -ignore "web/dist/**" -ignore ".genkit/**" .
   ```
3. Run the verification suite locally before opening a pull request:
   ```bash
   make lint
   make test
   ```
4. Open a pull request with a clear description of the problem and solution.

## Community Guidelines

This project follows [Google's Open Source Community Guidelines](https://opensource.google/conduct/). Please review [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.
