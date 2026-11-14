# scrub-proxy

scrub-proxy is a local proxy for the Anthropic Messages API. It removes secrets and
personal data from each request before the request leaves your computer. It puts the real
values back into the response.

## How it works

1. Claude Code sends a request to the proxy.
2. The proxy finds secrets and personal data in the text and in the images.
3. The proxy replaces each value with a placeholder, for example `PII_EMAIL_5d0d7350`.
4. The proxy sends the changed request to Anthropic.
5. Anthropic sends the response to the proxy.
6. The proxy replaces each placeholder with the real value.
7. The proxy sends the response to Claude Code.

The proxy keeps a table of placeholders and real values in a local SQLite database.
The same value always gets the same placeholder. This keeps prompt caching valid.

The proxy restores values with string replacement. No language model does this work.
This is also true for streamed responses and for the inputs of tool calls.

If the proxy cannot check a request, it does not send the request. This is "fail closed".

## What the proxy finds

| Data | Method |
|---|---|
| Email, IP address, phone number, social security number | Regular expression |
| Payment card number | Regular expression and Luhn check |
| Private key, JWT, credentials in a URL, Anthropic key | Regular expression |
| Vendor tokens, `password = ...` lines | detect-secrets and gitleaks |
| Random-looking strings | Entropy check on base64 characters |
| Name, street address | GLiNER model `knowledgator/gliner-pii-base-v1.0` |
| Text in an image | RapidOCR, then the same checks as for text |

The entropy check skips hexadecimal strings. This keeps git commit hashes readable.

## Requirements

- Python 3.12
- The `gitleaks` program, in a directory on `PATH`
- About 1.5 GB of disk space for the Python packages
- About 650 MB of disk space for the name model (the proxy downloads it at first start)
- No GPU
- The DejaVu Sans Mono font (optional, for the labels in images)

## Install

1. Make a virtual environment.

   ```sh
   python3 -m venv .venv
   ```

2. Install PyTorch for the CPU.

   ```sh
   .venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
   ```

3. Install the other packages.

   ```sh
   .venv/bin/pip install -r requirements.txt
   ```

4. Download `gitleaks` from its release page. Check the checksum of the file.
   Put the program in a directory on `PATH`.

At first start, the proxy downloads only the model files it needs.

## Start the proxy

```sh
.venv/bin/python -m scrub_proxy serve
```

The proxy listens on `127.0.0.1:8787`. It accepts connections from your computer only.

WARNING: The proxy has no login. Do not make the port reachable from other computers.
Each program that can reach the proxy can use your Anthropic credentials.

## Use the proxy with Claude Code

Set `ANTHROPIC_BASE_URL` for the Claude Code process:

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

The variable applies to this process only. A `claude` command without the variable sends
requests directly to Anthropic. These requests are not scrubbed.

The proxy sends your login credentials to Anthropic without a change. It does not store them.

## Use the proxy with images

The proxy accepts base64 images in PNG, JPEG, WebP and GIF format. For each image:

1. The proxy reads the text with OCR.
2. The proxy finds secrets and personal data in the text.
3. The proxy covers each value with a black shape. The shape follows the slant of the text.
4. The proxy writes the placeholder on the shape.
5. The proxy saves the image again. This removes the EXIF data, for example GPS position.

To see the result before you send an image, use this command:

```sh
.venv/bin/python -m scrub_proxy scan-image input.jpg preview.jpg
```

## Other commands

| Command | Result |
|---|---|
| `scan FILE` | Prints the scrubbed text of a file. Nothing is sent. |
| `lookup PLACEHOLDER` | Prints the real value of a placeholder. |
| `stats` | Prints the number of stored values for each type. |

## Settings

Set these environment variables before you start the proxy.

| Variable | Default | Effect |
|---|---|---|
| `SCRUB_PORT` | `8787` | Port of the proxy |
| `SCRUB_UPSTREAM` | `https://api.anthropic.com` | Address of the real API |
| `SCRUB_DATA_DIR` | `~/.local/share/scrub-proxy` | Folder for the database and files |
| `SCRUB_NER_MODEL` | `knowledgator/gliner-pii-base-v1.0` | Name model |
| `SCRUB_NER=0` | on | Turns off name and address detection |
| `SCRUB_IMAGES=0` | on | Turns off image checks. The proxy then rejects images. |
| `SCRUB_OCR_MAX_SIDE` | `3000` | Longest image side, in pixels, for OCR |
| `SCRUB_ALLOW_BINARY=1` | off | Sends PDFs and URL images without a check |
| `SCRUB_PASSTHROUGH_POST` | none | Extra POST paths that the proxy sends without a check |
| `SCRUB_NOTE=0` | on | Does not add the placeholder note to the system prompt |
| `SCRUB_DUMP_DIR` | none | Saves a copy of each outgoing request |

WARNING: `SCRUB_DUMP_DIR` stores your prompts. Delete the folder when you finish.

The data folder holds these files:

| File | Content |
|---|---|
| `map.db` | Placeholders, real values and cached scan results |
| `key` | Secret key for the placeholder names |
| `always.json` | Values to scrub every time, for example `{"Jane Doe": "NAME"}` |
| `allow.txt` | Values to never scrub. Use one value for each line. |

Restart the proxy after you change `always.json` or `allow.txt`.

The name detector misses some names. Put the names you know in `always.json`.

## Errors

The proxy does not send a request that it cannot check. It returns an error instead.

| Status | Cause |
|---|---|
| 400 | An image the proxy cannot read, an image from a URL or a file ID, a PDF, or an unknown block type |
| 403 | A POST to a path other than `/v1/messages` and `/v1/messages/count_tokens` |
| 502 | A detector failed |

The proxy log shows the cause.

## Tests

```sh
.venv/bin/python -m pytest -q
```

The tests put fake secrets and personal data into requests, images and streamed
responses. A test fails if one fake value reaches the mock upstream server. The tests also
check that the real values return in the response.

## Test results

The numbers are from a laptop with a 4-core CPU and no GPU.

| Item | Result |
|---|---|
| Name model, new text | About 0.4 s for each KB of text with capital letters |
| Text that the proxy scanned before | About 4 ms for 78 KB |
| First request of a Claude Code session | About 25 s. The proxy saves the result. |
| Typical later request | 0.7 s to 8 s. The time depends on the new tool output. |
| False positives in 78 KB of source code and file listings | 0 |
| One 1800 by 900 pixel photo | About 4 s. The proxy saves the result. |

A local language model on the same laptop is too slow for this work. It reads about
20 tokens each second.

## Limits

- The proxy protects only the requests that Claude Code sends to the Messages API through
  `ANTHROPIC_BASE_URL`. Other traffic does not use the proxy. Examples are MCP servers
  and web tools.
- In images, the proxy protects only the text that OCR can read. Faces, handwriting, very
  small text, blurred text, QR codes and barcodes are not protected.
- The proxy uses only the first frame of an animated image.
- The proxy does not find parts or encodings of a value, for example the base64 form of
  a key.
- The name model misses names in lowercase letters. It also misses single first names.
- The model can cut a placeholder in an answer. The system note reduces this problem.
- The database in the data folder holds the real values as plain text. Only the file
  owner can read it.
- A large tool output that the proxy has not seen before adds delay. A 50 KB file adds
  about 20 s.

## Security notes

- Keep the proxy on the local interface.
- Keep the data folder private. Do not put it in a backup that others can read.
- The proxy is a prototype. It reduces the risk of a leak. It does not remove the risk.
- Look at the saved requests with `SCRUB_DUMP_DIR` before you trust the proxy with
  important data.

## AI authorship

Claude (Anthropic) wrote the code, the tests and this README. The repository owner set the
goal and the design. Claude ran the tests.
