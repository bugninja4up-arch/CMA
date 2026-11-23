# Anomaly-Engineer

An early-stage, evidence-driven security research assistant with an interactive command-line interface. It supports OpenAI-compatible providers, stores research notes in SQLite, and can load local Markdown skills.

**Current status:** this is an early prototype, not an autonomous scanner. It now has a bounded HTTP differential tool and an offline JavaScript source analyzer. Browser automation and reconnaissance remain placeholders. Do not treat the assistant's hypotheses or scanner signals as confirmed findings.

## Requirements

- Python 3.10 or newer
- An API key for the chosen hosted provider, or a locally running Ollama instance with a suitable model

## Install and run

```bash
git clone https://github.com/bugninja4up-arch/CMA.git
cd CMA
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
export OPENAI_API_KEY="your-api-key"  # Windows PowerShell: $env:OPENAI_API_KEY="your-api-key"
python main.py
```

Configure the provider, model, scope, and database path in `config.yaml`. For DeepSeek use `DEEPSEEK_API_KEY`; for Ollama configure the local endpoint and model. Never commit real keys, private research notes, or the generated database.

The program stores interactions in `evidence.db` by default. Configure `scope` before testing; it is empty by default. Every analysis or active tool call requires human approval. The HTTP tool accepts only GET/POST, sends a baseline plus at most three JSON type substitutions, uses a 5-second timeout, caps request/response bodies, sends no cookies, and does not follow redirects. `allowed_domains` covers only standard HTTP(S) ports; put a nonstandard port in an exact `allowed_urls` entry. Responses are summarized as status and hashes, not returned as raw bodies. The JavaScript analyzer works only on supplied text and redacts potential secret values.

## Tests

Run the local test suite with the standard library:

```bash
python -m unittest discover -s tests -v
```

Tests use synthetic inputs and a local HTTP server; they do not contact external targets.

## License

MIT. See [LICENSE](LICENSE).
