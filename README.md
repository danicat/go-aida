# AIDA (`go-aida`)

AIDA is an experimental host diagnostic and troubleshooting assistant built with [Genkit Go](https://genkit.dev) and [A2UI](https://a2ui.org).

Instead of returning walls of text, AIDA pairs live system telemetry from [`osquery`](https://osquery.io) with dynamic UI components (status panels, telemetry charts, gauges, and process tables). When an issue requires host changes, proposed shell commands pause for human-in-the-loop operator confirmation before running.

## Prerequisites

- **Go** (1.25+)
- **Node.js** (20+) and `npm`
- **`osqueryi`** installed and available on your system `PATH`:
  - macOS: `brew install --cask osquery`
  - Linux: see [osquery installation instructions](https://osquery.io/downloads/official)
- A **Gemini API key** (`GEMINI_API_KEY`) or Google Cloud project with Vertex AI credentials

## Quick Start

1. **Install dependencies and build the web frontend:**
   ```bash
   make setup
   make build-web
   ```

2. **Launch the web cockpit:**
   ```bash
   export GEMINI_API_KEY="your-api-key"
   make run
   ```
   Open [http://localhost:8080](http://localhost:8080) to access the diagnostic cockpit.

3. **Headless CLI mode:**
   Run a single diagnostic query directly from the terminal without starting the web server:
   ```bash
   go run . -prompt "Inspect top 5 processes by CPU and memory"
   ```

## Configuration

| Environment Variable | Description |
| :--- | :--- |
| `GEMINI_API_KEY` | Gemini Developer API key (Google AI). |
| `GOOGLE_CLOUD_PROJECT` | Google Cloud project ID (if using Vertex AI). |
| `GOOGLE_CLOUD_LOCATION` | Region for Vertex AI (defaults to `global`). |

Pass `-help` to `go-aida` to inspect optional CLI flags (listening address, custom prompt directories, or model overrides).

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

---

*This is an experimental personal project and reference implementation, not an officially supported Google product.*
