# TRMLabsTakeHome_ArjunRewari

Instructions to recreate:
```
Create a .env file with Gemini API key... GEMINI_API_KEY = abcd...
mkdir -p evidence
touch output.json
touch scans.db
docker build -t trm-crypto-agent .
docker run --rm -it \
  --env-file .env \
  -v "$(pwd)/agent.py:/app/agent.py" \
  -v "$(pwd)/output.json:/app/output.json" \
  -v "$(pwd)/evidence:/app/evidence" \
  -v "$(pwd)/scans.db:/app/scans.db" \
  trm-crypto-agent
  ```

System Design and Architecture Overview:
To ensure cross-platform consistency and easy deployment, the application is containerized in docker with volume mounts used to persist database state and evidence safely to the host machine. The seed urls are loaded into a SQLite database with WAL. I use the asyncio semaphore library to manage a pool of 5 concurrent browser workers, maximizing throughput while respecting LLM API rate limits.

Web navigation is handled by headless Chromium and every url is opened in a fresh, isolated browser context to prevent cookie bleed and session tracking between sites.

There are 3 layers to the extraction of addresses:
 - Visual: Screenshots fed to the LLM to catch addresses embedded in images.
 - DOM: Deep Regex scanning of innerText, raw HTML, hidden data-* attributes, and clipboard copy buttons.
 - Network: Intercepting live XHR/Fetch API responses to catch addresses loaded dynamically by Single Page Applications (React/Vue).

I used Gemini 2.5 Flash as the cognitive layer of this architecture. The VLA model receives the visual and textual state and returns a strictly typed JSON object via Pydantic Structured Outputs. It decides whether a website is a scam, assigns a confidence score, and where to click next to dig deeper into a website (up to 3 actions). I handled assumptions by passing a specific system prompt to the LLM instructing it exactly what criteria constitutes a scam.

Edge cases:

Inactive sites are handled via SQLite database logs them as FAILED, applies exponential backoff, and tries again. If they fail 3 times, they are gracefully marked as DEAD.

If a site is a scam but no addresses are found the extraction list will just remain empty and the agent proceeds normally.

When scam sites block JavaScript execution I wrapped page.inner_text in a try/except block ensuring that it gracefully falls back to an empty string and relies on the visual screenshot instead of crashing.

```
Output Schema:
[
    {
        "url",
        "classification",
        "confidence",
        "extracted_addresses":[],
        "reasoning"
    }
]
```

Alternative approaches considered:
- Originally I was using the LLM only to read and output crypto addresses. However, LLMs are known to hallucinate so I opted for a hybrid approach, using Regex to extract addresses to reduce this likelihood.

- I decided to use playwright over something like beautiful soup because of the potential javascript execution that would be needed to render any addresses or scams.

- I strongly considered using something like langgraph to orchestrate the reasoning and action loop but I wanted to avoid the overhead of this abstraction layer. A web crawling agent requires low level control over network interceptions and browser timeouts. I also thought that the overall system would not be complex enough to need it.

- I considered using an in memory queue over sqlite but I was dealing with frequent crashes and unstable sites so persisting state to disk ensures the crawler can restart and resume seamlessly after a failure.

- I considered using other VLA models like Claude or GPT but as far as I am aware, Gemini is the best for long context, so I think in terms of future scaling when working on websites that might require many different actions Gemini might be best.

Unique and creative brought to solution:
- Exponential backoff for API throttling. The free tier of gemini API limits requests to 15 per minute. I used wait = (2 ** attempt) * 10 to wait without dropping the URL.

- I added background network interception in case an address is fetched when a user clicks deposit or another such button.

- I added pre-processing of the site by dismissing any pop-ups or overlays before handing off to the LLM.

What I would do with more time:
- I think it would be interesting to explore something like a rotating  proxy pool in case a DNS blocks certain IPs.

- I think it would have been interesting to explore how to deal with CAPTCHA challenges.

- It would be cool to explore on chain verification to verify that a wallet is a scam wallet.

- I would also want to try out different models and see which one would work best for this kind of task, especially with sites that require a much longer context/actions with more than 3 layers of actions.

- If I had more time I would also like to explore using a message queue rather than the current SQLite polling loop because this would work better at scale. Right now my script acts as both the manager and the worker, so a message queue could be used to decouple these.

- For further scaling if I needed to run hundreds of browsers I would containerize the worker logic and deploy it to Kubernetes, automatically spinning up more containers when the message queue gets backed up.

- It would also be interesting to explore using an LLM Gateway to act as a load balancer for requests across different api keys and fallback to different models. I would also like to add more pre processing steps using NLP like a fine tuned BERT model to recognize keywords as this would reduce the cost of calling the LLM api everytime we need a task done.