# VulNews

VulNews is a fast-reaction vulnerability notifier for SUSE/openSUSE. It monitors RSS feeds of security-related websites, uses Large Language Models (LLMs) to detect potential supply chain compromises, and automatically checks the openSUSE Build Service (OBS) for potential impact.

## How it Works

VulNews operates through a multi-stage pipeline:

1.  **Ingestion**: Subscribes to configured sources—RSS/Atom feeds, JSON Feeds (RFC 8927), or the GitHub Advisory Database—to fetch the latest articles and advisories. It uses ETag, Last-Modified headers, and API-specific caching to efficiently poll for new content.
2.  **Analysis**: Each new article is analyzed by an LLM (locally via `llama-cpp-python`, via **Ollama API**, or externally via a command-line tool) to determine if it describes a *confirmed* supply chain compromise.
3.  **Extraction & Integration**: If a compromise is detected, the LLM extracts key details (affected package name, ecosystem, version range, and compromised timeframe). For structured sources like GitHub Advisories, **Structured Bypass** ensures that machine-readable fields (like precise semantic version ranges) are preserved without LLM-induced "lossy" conversion.
4.  **Deduplication**: Checks a local database to ensure the compromise hasn't been reported before.
5.  **Impact Assessment**: Uses `osc` (openSUSE Commander) to search for the affected package in OBS. If found, it performs **semantic version range matching** to determine if the local version is vulnerable. It also analyzes changelogs and source listings to determine if the package was updated during the compromised window or contains known malicious files.
6.  **Reporting**: Outputs detailed findings to STDOUT, including a risk assessment.

## Requirements

-   **Python**: 3.12 or newer.
-   **osc**: The `osc` command-line tool must be installed and configured for OBS impact assessment.
    -   On openSUSE/SUSE: `sudo zypper install osc`
-   **Local LLM (Optional)**: If using the local LLM, a compatible GGUF model is required (automatically downloaded by default).
    -   *Security Note*: The local LLM uses `diskcache`, which has a known vulnerability (`CVE-2025-69872`). As a mitigation, ensure that the `state_dir` (where the cache resides) is not writable by untrusted users.

## Installation

It is recommended to install VulNews in a virtual environment. You can use the provided `Makefile` for a quick setup:

```bash
# Clone the repository
git clone https://github.com/vojtechpavlik/vulnews.git
cd vulnews

# Setup virtual environment and install dependencies
make install
```

Alternatively, manual installation:

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install the package with test dependencies
pip install -e ".[test]"
```

## Testing

VulNews includes a comprehensive suite of unit and integration tests.

```bash
# Run all tests via Makefile
make test

# Or run pytest directly
pytest
```

There is also a synthetic end-to-end test that simulates a full pipeline run with a local RSS server:

```bash
# Requires a local GGUF model to be configured/downloaded
make test-synthetic
```

## Configuration

Copy the example configuration and adjust it to your needs:

```bash
cp config.example.yaml config.yaml
```

### Key Configuration Options:

-   `poll_interval`: Interval in seconds between polls when running as a daemon.
-   `llm_type`: `local` (internal llama-cpp-python), `ollama` (external Ollama API), or `external` (calls an external command).
-   `llm_local_model_repo` / `llm_local_model_file`: Hugging Face repository and filename for the local model.
-   `llm_ollama_url` / `llm_ollama_model`: URL and model name for Ollama API.
-   `llm_local_chat_template`: Chat template format for local LLM (e.g., `nemo`, `llama-3`, `generic`).
-   `llm_command`: Command to run for external LLM analysis (e.g., using Gemini CLI).
-   `sources`: List of feeds to monitor. Supported types: `rss` (RSS/Atom), `json` (JSON Feed), and `github_advisory` (GitHub Advisory REST API).
-   `state_dir`: Directory where persistent data is stored.

## Usage

Run VulNews by pointing it to your configuration file:

```bash
# Run as a daemon (continuous polling)
vulnews -c config.yaml

# Run once and exit
vulnews -c config.yaml --one-shot

# Test a specific source
vulnews -c config.yaml --one-shot --source phylum

# Dry run (fetch feeds but skip LLM and OBS checks)
vulnews -c config.yaml --one-shot --dry-run
```

### Command-line Arguments:

-   `-c, --config PATH`: **(Required)** Path to the YAML configuration file.
-   `--one-shot`: Poll all sources once and exit instead of running as a daemon.
-   `--source NAME`: Poll only the specified named source.
-   `--dry-run`: Fetch feeds but skip LLM analysis and OBS search.
-   `-v, --verbose`: Enable debug logging.

## Deployment & Hardening

For production environments, follow these recommendations:

### 1. Restricted Permissions
The `state_dir` contains cached data and potentially sensitive compromise logs. Restrict access to the user running `vulnews`:
```bash
chmod 700 ./state
```
This is particularly important to mitigate risks from transitive dependencies like `diskcache`.

### 2. Authentication
- **OBS (osc)**: Ensure `osc` is configured with valid credentials in `~/.oscrc`. Use token-based authentication if possible.
- **GitHub**: Set the `GITHUB_TOKEN` environment variable to avoid rate limits when polling the Advisory Database:
  ```bash
  export GITHUB_TOKEN=your_token_here
  ```

### 3. Running as a Service (systemd)
Create a unit file `/etc/systemd/system/vulnews.service`:
```ini
[Unit]
Description=VulNews Supply Chain Monitor
After=network.target

[Service]
Type=simple
User=vulnews
WorkingDirectory=/opt/vulnews
ExecStart=/usr/bin/vulnews -c /etc/vulnews/config.yaml
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

### 4. Hardening Checklist
- [ ] Run as a dedicated non-privileged user.
- [ ] Use `HTTPS` for all source URLs.
- [ ] Ensure `state_dir` is on a persistent volume with restricted permissions.
- [ ] Monitor logs for `RedactingFilter` activity to ensure no secrets are leaking.
- [ ] Use a local LLM for maximum privacy, or a trusted external provider.

## State Management

VulNews maintains state in the directory specified by `state_dir` (default: `./state`):

-   `feed_state.json`: Stores ETags and timestamps for RSS feeds to avoid re-downloading unchanged content.
-   `compromises.json`: A database of detected compromises to prevent duplicate reports.
-   `models/`: Directory where locally downloaded LLM models are cached.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
