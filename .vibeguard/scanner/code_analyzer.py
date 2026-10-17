import re
from typing import List, Dict, Any
from utils.logger import get_logger

logger = get_logger(__name__)


def analyze_api_route(code: str) -> List[Dict[str, Any]]:
    """
    Analyze pasted API route code for security issues.
    Works with Next.js API routes, Express, FastAPI etc.
    """
    findings = []

    # ── 1. Missing auth check ─────────────────────────────────────────────────
    auth_patterns = [
        r'getServerSession',
        r'getSession',
        r'auth\(\)',
        r'verifyToken',
        r'requireAuth',
        r'isAuthenticated',
        r'req\.user',
        r'request\.user',
        r'session\(',
        r'jwt\.verify',
        r'supabase\.auth\.getUser',
        r'supabase\.auth\.getSession',
        r'req\.headers\[.authorization.\]',
        r'Authorization',
    ]

    has_auth = any(
        re.search(pattern, code, re.IGNORECASE)
        for pattern in auth_patterns
    )

    has_handler = bool(re.search(
        r'(export\s+default\s+(?:async\s+)?function|'
        r'app\.(get|post|put|delete|patch)|'
        r'router\.(get|post|put|delete)|'
        r'@app\.route|'
        r'async def \w+.*request)',
        code,
        re.IGNORECASE
    ))

    if has_handler and not has_auth:
        findings.append({
            "id": "api_no_auth",
            "name": "API Route Has No Authentication Check",
            "severity": "critical",
            "category": "Missing Authentication",
            "technical": (
                "No authentication verification found in this route handler. "
                "No calls to getServerSession, getSession, jwt.verify, "
                "supabase.auth.getUser, or similar auth checks detected."
            ),
            "business": (
                "This API endpoint can be called by anyone — "
                "logged in or not. Attackers can discover this URL "
                "from your JS bundle and call it directly. "
                "Add an authentication check as the very first thing in the handler."
            ),
            "evidence": "No auth check pattern found in handler",
            "fix": (
                "// Next.js App Router — add at top of route:\n"
                "const session = await getServerSession(authOptions);\n"
                "if (!session) {\n"
                "  return Response.json({ error: 'Unauthorized' }, { status: 401 });\n"
                "}\n\n"
                "// Supabase:\n"
                "const { data: { user } } = await supabase.auth.getUser();\n"
                "if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });"
            )
        })

    # ── 2. AI service called without rate limiting ────────────────────────────
    ai_patterns = [
        r'openai\.chat',
        r'openai\.completions',
        r'anthropic\.messages',
        r'claude\.',
        r'gemini\.',
        r'new OpenAI',
        r'new Anthropic',
        r'createCompletion',
        r'chatCompletion',
    ]

    has_ai_call = any(
        re.search(p, code, re.IGNORECASE)
        for p in ai_patterns
    )

    rate_limit_patterns = [
        r'rateLimit',
        r'rate_limit',
        r'rateLimiter',
        r'upstash',
        r'redis',
        r'slowDown',
        r'429',
        r'Too Many',
    ]

    has_rate_limit = any(
        re.search(p, code, re.IGNORECASE)
        for p in rate_limit_patterns
    )

    if has_ai_call and not has_rate_limit:
        findings.append({
            "id": "api_ai_no_rate_limit",
            "name": "AI API Call Without Rate Limiting",
            "severity": "critical",
            "category": "Missing Rate Limiting",
            "technical": (
                "An AI service call (OpenAI, Anthropic, etc.) was found "
                "in this route with no rate limiting detected. "
                "No rateLimit, redis, upstash, or 429 handling found."
            ),
            "business": (
                "A single attacker can call this endpoint in a loop all night. "
                "Every call costs you money. "
                "Real vibe-coded apps have received $50,000 AI bills from a single attack. "
                "Add server-side rate limiting immediately — "
                "Upstash Redis is free and takes 10 minutes to add."
            ),
            "evidence": "AI call found, no rate limiting pattern detected",
            "fix": (
                "// Add Upstash rate limiting (free tier available):\n"
                "import { Ratelimit } from '@upstash/ratelimit';\n"
                "import { Redis } from '@upstash/redis';\n\n"
                "const ratelimit = new Ratelimit({\n"
                "  redis: Redis.fromEnv(),\n"
                "  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 req/min\n"
                "});\n\n"
                "const { success } = await ratelimit.limit(userId);\n"
                "if (!success) return Response.json({ error: 'Rate limited' }, { status: 429 });"
            )
        })

    # ── 3. Direct DB query without ownership filter ───────────────────────────
    db_query_patterns = [
        r'\.from\s*\(["\`]\w+["\`]\)\s*\.select',
        r'SELECT\s+\*\s+FROM',
        r'db\.query',
        r'prisma\.\w+\.findMany',
        r'prisma\.\w+\.findFirst',
    ]

    ownership_patterns = [
        r'user_id',
        r'userId',
        r'auth\.uid',
        r'session\.user',
        r'req\.user\.id',
        r'where.*id.*=',
        r'\.eq\(',
        r'\.filter\(',
    ]

    has_db_query = any(
        re.search(p, code, re.IGNORECASE)
        for p in db_query_patterns
    )

    has_ownership_filter = any(
        re.search(p, code, re.IGNORECASE)
        for p in ownership_patterns
    )

    if has_db_query and not has_ownership_filter:
        findings.append({
            "id": "api_unfiltered_query",
            "name": "Database Query Without User Ownership Filter",
            "severity": "high",
            "category": "Insecure Direct Object Reference (IDOR)",
            "technical": (
                "A database query was found with no user ownership filter. "
                "No user_id, userId, .eq(), or session-based filter detected. "
                "This may return all rows regardless of which user is requesting."
            ),
            "business": (
                "This query may return data belonging to all users, "
                "not just the logged-in user. "
                "User A could retrieve User B's orders, messages, or private data "
                "just by calling this endpoint. "
                "Always filter queries by the authenticated user's ID."
            ),
            "evidence": "DB query found without ownership filter",
            "fix": (
                "// Always filter by authenticated user:\n"
                "const { data: { user } } = await supabase.auth.getUser();\n\n"
                "// Supabase — RLS handles this if configured correctly:\n"
                "const { data } = await supabase\n"
                "  .from('posts')\n"
                "  .select('*')\n"
                "  .eq('user_id', user.id); // explicit filter as backup\n\n"
                "// Prisma:\n"
                "const posts = await prisma.post.findMany({\n"
                "  where: { userId: session.user.id }\n"
                "});"
            )
        })

    # ── 4. Stripe secret key used in route ────────────────────────────────────
    stripe_secret = re.search(
        r'new\s+Stripe\s*\(\s*["\`]sk_live_',
        code
    )
    if stripe_secret:
        findings.append({
            "id": "api_stripe_hardcoded",
            "name": "Stripe Live Secret Key Hardcoded in Route",
            "severity": "critical",
            "category": "Hardcoded Secret",
            "technical": "Stripe live secret key (sk_live_) found hardcoded in route code.",
            "business": (
                "Your Stripe secret key is hardcoded in source code. "
                "If this code is ever pushed to GitHub (even a private repo), "
                "the key is compromised. Move it to an environment variable immediately."
            ),
            "evidence": "sk_live_ found as literal string",
            "fix": (
                "// Use environment variable instead:\n"
                "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\n\n"
                "// In .env (never commit this file):\n"
                "STRIPE_SECRET_KEY=sk_live_your_key_here"
            )
        })

    # ── 5. No input validation ────────────────────────────────────────────────
    has_user_input = bool(re.search(
        r'req\.body|request\.json|params\.|query\.',
        code, re.IGNORECASE
    ))

    validation_patterns = [
        r'zod', r'yup', r'joi', r'z\.object',
        r'z\.string', r'\.parse\(', r'\.validate\(',
        r'typeof.*===', r'if\s*\(.*length',
    ]

    has_validation = any(
        re.search(p, code, re.IGNORECASE)
        for p in validation_patterns
    )

    if has_user_input and not has_validation:
        findings.append({
            "id": "api_no_validation",
            "name": "API Route Accepts User Input Without Validation",
            "severity": "medium",
            "category": "Missing Input Validation",
            "technical": (
                "User input (req.body, request.json, params) is used "
                "without any validation library (zod, yup, joi) or manual checks."
            ),
            "business": (
                "Unvalidated input can be used to send unexpected data types, "
                "empty values, or malicious strings that crash your server "
                "or corrupt your database. Add input validation."
            ),
            "evidence": "User input used without validation pattern",
            "fix": (
                "// Use Zod for validation (recommended):\n"
                "import { z } from 'zod';\n\n"
                "const schema = z.object({\n"
                "  name: z.string().min(1).max(100),\n"
                "  email: z.string().email(),\n"
                "});\n\n"
                "const body = schema.parse(await request.json());"
            )
        })

    # ── 6. NEW: JWT decode without verify ─────────────────────────────────────
    has_jwt_decode = bool(re.search(r'jwt\.decode\s*\(', code, re.IGNORECASE))
    has_jwt_verify = bool(re.search(r'jwt\.verify\s*\(', code, re.IGNORECASE))

    if has_jwt_decode and not has_jwt_verify:
        findings.append({
            "id": "jwt_decode_no_verify",
            "name": "JWT Decoded But Signature Not Verified",
            "severity": "critical",
            "category": "Broken Authentication",
            "technical": (
                "jwt.decode() is used without jwt.verify(). "
                "decode() simply splits and base64-decodes the token without "
                "checking the cryptographic signature. This means anyone can forge "
                "a token with any payload (e.g., admin: true) and it will be accepted."
            ),
            "business": (
                "Your authentication is completely broken. Anyone can create a fake token "
                "claiming to be any user, including admins, and your app will trust it. "
                "Replace jwt.decode() with jwt.verify(token, secret) immediately."
            ),
            "evidence": "jwt.decode() found without jwt.verify()",
            "fix": (
                "// WRONG — never use decode() for auth:\n"
                "// const user = jwt.decode(token);\n\n"
                "// CORRECT — always verify the signature:\n"
                "const user = jwt.verify(token, process.env.JWT_SECRET);\n"
                "// jwt.verify() throws an error if the token is invalid or expired\n"
                "// Wrap in try/catch to handle invalid tokens gracefully"
            )
        })

    # ── 7. NEW: dangerouslySetInnerHTML ───────────────────────────────────────
    dangerous_html_match = re.search(
        r'dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:\s*(?!.*["\'])',
        code
    )
    # Also catch the general pattern
    if not dangerous_html_match:
        dangerous_html_match = re.search(r'dangerouslySetInnerHTML', code)
        if dangerous_html_match:
            # Check if it's using a variable (not a static string)
            context = code[max(0, dangerous_html_match.start()-20):dangerous_html_match.end()+100]
            if any(var_indicator in context for var_indicator in ['{', 'content', 'html', 'data', 'body', 'text', 'input', 'value']):
                dangerous_html_match = dangerous_html_match
            else:
                dangerous_html_match = None

    if dangerous_html_match:
        findings.append({
            "id": "dangerous_set_inner_html",
            "name": "dangerouslySetInnerHTML Used — Potential XSS",
            "severity": "high",
            "category": "Cross-Site Scripting (XSS)",
            "technical": (
                "dangerouslySetInnerHTML is used in this component. "
                "React's XSS protection is bypassed when using this prop. "
                "If the HTML content comes from any user-controlled source or external API, "
                "malicious scripts can be injected and executed in users' browsers."
            ),
            "business": (
                "If any user-controlled data reaches dangerouslySetInnerHTML, "
                "attackers can inject scripts that steal session tokens, redirect users to "
                "phishing pages, or take over accounts. "
                "Sanitize all HTML with DOMPurify before rendering, or refactor to avoid this prop."
            ),
            "evidence": "dangerouslySetInnerHTML found in component",
            "fix": (
                "// Install DOMPurify:\n"
                "// npm install dompurify @types/dompurify\n\n"
                "import DOMPurify from 'dompurify';\n\n"
                "// UNSAFE:\n"
                "// <div dangerouslySetInnerHTML={{ __html: userContent }} />\n\n"
                "// SAFE:\n"
                "const clean = DOMPurify.sanitize(userContent);\n"
                "<div dangerouslySetInnerHTML={{ __html: clean }} />"
            )
        })

    # ── 8. NEW: eval() with variable input ───────────────────────────────────
    eval_match = re.search(r'\beval\s*\(\s*(?!["\'])', code)
    if eval_match:
        findings.append({
            "id": "eval_with_variable",
            "name": "eval() Called With Dynamic Input — Code Injection Risk",
            "severity": "critical",
            "category": "Code Injection",
            "technical": (
                "eval() is called with what appears to be a dynamic/variable argument. "
                "eval() executes arbitrary JavaScript code — if user input reaches it, "
                "an attacker can run any code in your application context."
            ),
            "business": (
                "eval() with user input is one of the most dangerous patterns in JavaScript. "
                "An attacker can execute any code: steal data, delete records, "
                "exfiltrate secrets, or take over the server process. "
                "Never use eval(). Use JSON.parse() for data or refactor the logic."
            ),
            "evidence": "eval() called with non-literal argument",
            "fix": (
                "// If parsing JSON:\n"
                "// WRONG: eval(userInput)\n"
                "// RIGHT: JSON.parse(userInput)\n\n"
                "// If executing dynamic code — refactor to use a lookup table:\n"
                "const actions = { 'greet': () => 'hello', 'bye': () => 'goodbye' };\n"
                "const result = actions[userInput]?.(); // safe alternative"
            )
        })

    # ── 9. NEW: SQL string concatenation ─────────────────────────────────────
    sql_injection_match = re.search(
        r'["\`](SELECT|INSERT|UPDATE|DELETE|DROP)\s[^"]+["\`]\s*\+\s*\w',
        code, re.IGNORECASE
    )
    if not sql_injection_match:
        # Also catch template literals with SQL
        sql_injection_match = re.search(
            r'`(SELECT|INSERT|UPDATE|DELETE)\s[^`]*\$\{(?!params\[|sanitize|escape)',
            code, re.IGNORECASE
        )

    if sql_injection_match:
        findings.append({
            "id": "sql_string_concat",
            "name": "SQL Query Built With String Concatenation — SQL Injection Risk",
            "severity": "critical",
            "category": "SQL Injection",
            "technical": (
                "A SQL query is being constructed using string concatenation or "
                "unparameterized template literals. This is the classic SQL injection pattern. "
                "User-controlled values should never be inserted directly into SQL strings."
            ),
            "business": (
                "SQL injection allows attackers to bypass authentication, dump your entire database, "
                "delete all data, or execute commands on the server. "
                "This is the #1 most exploited web vulnerability. "
                "Use parameterized queries or an ORM (Prisma, Drizzle) immediately."
            ),
            "evidence": "SQL string concatenation pattern detected",
            "fix": (
                "// WRONG — SQL injection vulnerable:\n"
                "// db.query('SELECT * FROM users WHERE id=' + userId)\n\n"
                "// RIGHT — parameterized query:\n"
                "db.query('SELECT * FROM users WHERE id = $1', [userId])\n\n"
                "// Or use an ORM (Prisma):\n"
                "const user = await prisma.user.findUnique({ where: { id: userId } });"
            )
        })

    # ── 10. NEW: Math.random() for security tokens ───────────────────────────
    math_random_match = re.search(r'Math\.random\(\)', code)
    if math_random_match:
        # Check if it's near security-sensitive contexts
        context_start = max(0, math_random_match.start() - 200)
        context_end = min(len(code), math_random_match.end() + 200)
        context = code[context_start:context_end].lower()

        security_context = any(
            kw in context for kw in [
                "token", "password", "secret", "key", "reset", "otp",
                "verification", "confirm", "session", "nonce", "code", "pin"
            ]
        )

        if security_context:
            findings.append({
                "id": "math_random_security",
                "name": "Math.random() Used for Security-Sensitive Token Generation",
                "severity": "high",
                "category": "Insecure Randomness",
                "technical": (
                    "Math.random() is used near security-sensitive code (tokens, passwords, sessions). "
                    "Math.random() is a pseudo-random number generator — it is NOT cryptographically secure "
                    "and its output can be predicted if the attacker knows the seed."
                ),
                "business": (
                    "Password reset links, OTP codes, or session tokens generated with Math.random() "
                    "can be predicted by attackers. This allows account takeover without knowing the user's password. "
                    "Use crypto.randomUUID() or crypto.getRandomValues() instead."
                ),
                "evidence": "Math.random() used in security-sensitive context",
                "fix": (
                    "// WRONG — predictable:\n"
                    "// const token = Math.random().toString(36).substr(2)\n\n"
                    "// RIGHT — cryptographically secure (Node.js):\n"
                    "import { randomBytes } from 'crypto';\n"
                    "const token = randomBytes(32).toString('hex');\n\n"
                    "// Browser/Edge:\n"
                    "const token = crypto.randomUUID(); // UUID v4\n"
                    "// Or: crypto.getRandomValues(new Uint8Array(32))"
                )
            })

    # ── 11. NEW: postMessage without origin check ─────────────────────────────
    postmessage_match = re.search(r"addEventListener\s*\(\s*['\"]message['\"]", code)
    if postmessage_match:
        # Check if origin validation is present
        origin_check = bool(re.search(
            r'event\.origin|e\.origin|origin\s*!==|origin\s*===|allowedOrigins',
            code
        ))
        if not origin_check:
            findings.append({
                "id": "postmessage_no_origin_check",
                "name": "postMessage Listener Without Origin Validation",
                "severity": "medium",
                "category": "Cross-Origin Vulnerability",
                "technical": (
                    "A 'message' event listener was found without checking event.origin. "
                    "Any website can send postMessage events to your page. "
                    "Without origin validation, a malicious site can send crafted messages "
                    "to trigger actions in your app."
                ),
                "business": (
                    "Malicious websites can send fake messages to your app and trick it into "
                    "performing actions (redirects, data submission, UI changes) on behalf of the attacker. "
                    "Always validate event.origin before processing any postMessage data."
                ),
                "evidence": "addEventListener('message') found without event.origin check",
                "fix": (
                    "window.addEventListener('message', (event) => {\n"
                    "  // Always validate origin first\n"
                    "  const ALLOWED_ORIGIN = 'https://your-trusted-domain.com';\n"
                    "  if (event.origin !== ALLOWED_ORIGIN) return;\n\n"
                    "  // Now safe to process event.data\n"
                    "  handleMessage(event.data);\n"
                    "});"
                )
            })

    # ── FINAL BATCH: 7 NEW CODE CHECKS ───────────────────────────────────────

    # ── 12. Hardcoded admin / default credentials ─────────────────────────────
    COMMON_WEAK_PASSWORDS = [
        'admin', 'password', 'password123', '123456', 'test', 'demo',
        'secret', 'qwerty', 'letmein', 'welcome', 'changeme', 'default',
    ]
    hardcoded_cred_pattern = '|'.join(
        rf'(?:password|passwd|pwd|pass|secret|credential)[\s]*[=:][\s]*["\'](?:{p})["\']'
        for p in COMMON_WEAK_PASSWORDS
    )
    hardcoded_match = re.search(hardcoded_cred_pattern, code, re.IGNORECASE)
    if hardcoded_match:
        findings.append({
            "id": "hardcoded_admin_credentials",
            "name": "Hardcoded Weak/Admin Credentials Detected",
            "severity": "critical",
            "category": "Hardcoded Credentials",
            "technical": (
                f"A hardcoded weak password or default credential was found: "
                f"'{hardcoded_match.group(0)[:60]}'. "
                "Default credentials are the first thing attackers try."
            ),
            "business": (
                "Hardcoded default credentials are one of the most common entry points for attackers. "
                "If this code reaches production or a public repo, any attacker can immediately authenticate. "
                "Remove all hardcoded credentials and use environment variables."
            ),
            "evidence": hardcoded_match.group(0)[:80],
            "fix": (
                "// WRONG:\n"
                "// const password = 'admin';\n\n"
                "// RIGHT:\n"
                "const password = process.env.ADMIN_PASSWORD;\n"
                "// Never hardcode credentials in source code."
            )
        })

    # ── 13. MD5 or plaintext password storage ─────────────────────────────────
    md5_password_patterns = [
        r'md5\s*\([^)]*password[^)]*\)',
        r'hashlib\.md5',
        r'createHash\s*\(["\']md5["\']\)',
        r'crypto\.createHash\s*\(["\']md5["\']\)',
    ]
    has_md5_password = any(re.search(p, code, re.IGNORECASE) for p in md5_password_patterns)
    plaintext_compare = bool(re.search(
        r'(?:password|passwd)\s*===?\s*(?:req\.|request\.)',
        code, re.IGNORECASE
    ))

    if has_md5_password:
        findings.append({
            "id": "md5_password_hashing",
            "name": "MD5 Used for Password Hashing — Cryptographically Broken",
            "severity": "critical",
            "category": "Insecure Password Storage",
            "technical": (
                "MD5 is not a password hashing algorithm — it is a message digest. "
                "MD5 hashes for common passwords are precomputed in rainbow tables. "
                "Attackers can crack any MD5 password hash in seconds using free online tools."
            ),
            "business": (
                "If your database is breached, every user's password is instantly recoverable. "
                "This means full account takeover for all your users. "
                "Switch to bcrypt, Argon2, or scrypt immediately."
            ),
            "evidence": "MD5 hash used for password storage",
            "fix": (
                "// WRONG:\n// md5(password)\n\n"
                "// RIGHT (bcrypt):\n"
                "import bcrypt from 'bcryptjs';\n"
                "const hash = await bcrypt.hash(password, 12);\n"
                "const isValid = await bcrypt.compare(plaintext, hash);"
            )
        })

    if plaintext_compare:
        findings.append({
            "id": "plaintext_password_compare",
            "name": "Password Compared in Plaintext Without Hashing",
            "severity": "critical",
            "category": "Insecure Password Storage",
            "technical": (
                "A password is being compared directly from the request to a stored value "
                "without any hashing. Passwords must be hashed with bcrypt/Argon2 "
                "and compared using a constant-time function."
            ),
            "business": (
                "Plaintext password storage means a single database breach exposes every user's password. "
                "This violates GDPR, PCI-DSS, and common security standards."
            ),
            "evidence": "Direct plaintext password comparison detected",
            "fix": "const isValid = await bcrypt.compare(req.body.password, storedHash);"
        })

    # ── 14. Insecure fetch() without error handling ───────────────────────────
    fetch_calls = list(re.finditer(r'\bfetch\s*\(', code))
    has_error_handling = bool(re.search(
        r'\.catch\(|catch\s*\(|onError\s*=',
        code, re.IGNORECASE
    ))
    if fetch_calls and not has_error_handling:
        findings.append({
            "id": "fetch_no_error_handling",
            "name": "fetch() Calls Without Error Handling",
            "severity": "medium",
            "category": "Missing Error Handling",
            "technical": (
                f"Found {len(fetch_calls)} fetch() call(s) with no .catch() or try/catch error handling. "
                "Network errors, timeouts, and non-200 responses will silently fail."
            ),
            "business": (
                "Unhandled fetch errors cause silent failures that can corrupt app state, "
                "show blank screens to users, or expose raw error messages. "
                "Always handle fetch errors explicitly."
            ),
            "evidence": f"{len(fetch_calls)} unguarded fetch() call(s) found",
            "fix": (
                "try {\n"
                "  const res = await fetch('/api/data');\n"
                "  if (!res.ok) throw new Error(`HTTP ${res.status}`);\n"
                "  const data = await res.json();\n"
                "} catch (err) {\n"
                "  console.error('Request failed:', err);\n"
                "}"
            )
        })

    # ── 15. Prototype pollution ───────────────────────────────────────────────
    prototype_pollution_patterns = [
        r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.|request\.|body|params|query|user)',
        r'Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|request\.|body|params|query)',
        r'\bmerge\s*\(\s*\{[^}]*\}\s*,\s*(?:req\.|body|params|query)',
        r'_\.merge\s*\([^,]+,\s*(?:req\.|body|params)',
        r'deepmerge\s*\([^,]+,\s*(?:req\.|body|params)',
        r'\[\s*["\']__proto__["\']\s*\]',
    ]
    proto_match = next(
        (re.search(p, code, re.IGNORECASE) for p in prototype_pollution_patterns
         if re.search(p, code, re.IGNORECASE)),
        None
    )
    if proto_match:
        findings.append({
            "id": "prototype_pollution",
            "name": "Prototype Pollution Risk — Unsafe Object Merge With User Input",
            "severity": "high",
            "category": "Prototype Pollution",
            "technical": (
                f"User-controlled input merged into object without sanitizing dangerous keys "
                f"(__proto__, constructor, prototype). Pattern: '{proto_match.group(0)[:60]}'"
            ),
            "business": (
                "Prototype pollution lets attackers modify JavaScript's global Object.prototype, "
                "potentially bypassing security checks (isAdmin = true for everyone) "
                "or enabling remote code execution. Sanitize keys before merging."
            ),
            "evidence": proto_match.group(0)[:80],
            "fix": (
                "// SAFE — filter dangerous keys:\n"
                "const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];\n"
                "const safe = Object.fromEntries(\n"
                "  Object.entries(req.body).filter(([k]) => !FORBIDDEN.includes(k))\n"
                ");"
            )
        })

    # ── 16. Unvalidated file upload types ────────────────────────────────────
    upload_patterns = [
        r'multer\s*\(',
        r'formidable\s*\(',
        r'busboy\s*\(',
        r'upload\.single|upload\.array|upload\.fields',
        r'req\.file|req\.files',
    ]
    has_file_upload = any(re.search(p, code, re.IGNORECASE) for p in upload_patterns)
    file_validation_patterns = [
        r'mimetype', r'fileFilter', r'allowedTypes',
        r'file\.type', r'path\.extname', r'magic\s*byte|file-type',
    ]
    has_file_validation = any(re.search(p, code, re.IGNORECASE) for p in file_validation_patterns)

    if has_file_upload and not has_file_validation:
        findings.append({
            "id": "unvalidated_file_upload",
            "name": "File Upload Without MIME Type or Extension Validation",
            "severity": "high",
            "category": "Insecure File Upload",
            "technical": (
                "File upload handler (multer/formidable/busboy) found with no MIME type or "
                "extension validation. No mimetype check, fileFilter, or allowedTypes detected."
            ),
            "business": (
                "Without file type validation, attackers can upload web shells (remote code execution), "
                "malicious HTML (XSS), or oversized files (DoS). "
                "Validate MIME type AND extension, and store files outside webroot."
            ),
            "evidence": "File upload handler found without type validation",
            "fix": (
                "const upload = multer({\n"
                "  fileFilter: (req, file, cb) => {\n"
                "    const allowed = ['image/jpeg', 'image/png', 'image/webp'];\n"
                "    if (!allowed.includes(file.mimetype)) return cb(new Error('Invalid type'));\n"
                "    cb(null, true);\n"
                "  },\n"
                "  limits: { fileSize: 5 * 1024 * 1024 }\n"
                "});"
            )
        })

    # ── 17. child_process.exec() with user input (shell injection) ────────────
    exec_patterns = [
        r'exec\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)',
        r'execSync\s*\([^)]*(?:req\.|request\.|params\.|query\.)',
        r'spawn\s*\([^)]*(?:req\.|request\.|params\.|query\.)',
        r'require\s*\(["\']child_process["\']\)',
    ]
    exec_match = next(
        (re.search(p, code, re.IGNORECASE) for p in exec_patterns
         if re.search(p, code, re.IGNORECASE)),
        None
    )
    if exec_match:
        findings.append({
            "id": "shell_injection_exec",
            "name": "child_process.exec() With User Input — Shell Injection Risk",
            "severity": "critical",
            "category": "Shell Injection",
            "technical": (
                "child_process.exec() or execSync() detected with user-controlled input. "
                "Shell injection allows appending arbitrary commands via ;, |, &&, $(). "
                f"Pattern: '{exec_match.group(0)[:60]}'"
            ),
            "business": (
                "Shell injection gives attackers full server control: read/delete files, "
                "install backdoors, dump your database, or use your server as a botnet node. "
                "Use execFile() with an explicit argument array — never a shell string."
            ),
            "evidence": exec_match.group(0)[:80],
            "fix": (
                "// WRONG:\n// exec(`convert ${req.body.filename} output.png`)\n\n"
                "// SAFE — execFile with args array (no shell):\n"
                "import { execFile } from 'child_process';\n"
                "import path from 'path';\n"
                "const safeName = path.basename(filename);\n"
                "execFile('convert', [safeName, 'output.png'], (err, stdout) => { ... });"
            )
        })

    # ── 18. document.innerHTML / document.write DOM XSS ──────────────────────
    dom_xss_patterns = [
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'\.innerHTML\s*=\s*(?!["\'])',
        r'\.outerHTML\s*=\s*(?!["\'])',
        r'insertAdjacentHTML\s*\([^,]+,\s*(?!["\'])',
    ]
    dom_xss_match = next(
        (re.search(p, code) for p in dom_xss_patterns if re.search(p, code)),
        None
    )
    if dom_xss_match:
        findings.append({
            "id": "dom_xss_innerhtml",
            "name": "DOM-Based XSS Risk: innerHTML / document.write With Dynamic Content",
            "severity": "high",
            "category": "Cross-Site Scripting (XSS)",
            "technical": (
                "Direct DOM manipulation via innerHTML, outerHTML, insertAdjacentHTML, "
                "or document.write with a dynamic/variable value. "
                "If user-controlled data reaches these sinks, XSS is possible."
            ),
            "business": (
                "DOM XSS allows injecting malicious JavaScript: steal session tokens, "
                "redirect to phishing pages, log keystrokes, or take over the user's browser. "
                "Sanitize with DOMPurify or use textContent for plain text."
            ),
            "evidence": dom_xss_match.group(0)[:80],
            "fix": (
                "// WRONG:\n// element.innerHTML = userContent;\n\n"
                "// RIGHT:\n"
                "import DOMPurify from 'dompurify';\n"
                "element.innerHTML = DOMPurify.sanitize(userContent);\n\n"
                "// For plain text only:\n"
                "element.textContent = userContent;"
            )
        })

    # ── 19. Next.js Unprotected Server Actions ────────────────────────────────
    if 'use server' in code or '"use server"' in code or "'use server'" in code:
        if not has_auth:
            findings.append({
                "id": "unprotected_server_action",
                "name": "Unprotected Next.js Server Action",
                "severity": "critical",
                "category": "Missing Authentication",
                "technical": (
                    "A Next.js Server Action ('use server') was found without an authentication check. "
                    "Server actions are public API endpoints under the hood."
                ),
                "business": (
                    "Anyone on the internet can call this server action and bypass the frontend UI. "
                    "Always check authentication and authorization inside the action itself."
                ),
                "evidence": "'use server' directive found without auth check",
                "fix": (
                    "// Add auth check inside the action:\n"
                    "export async function myAction() {\n"
                    "  const session = await auth();\n"
                    "  if (!session) throw new Error('Unauthorized');\n"
                    "  // ...\n"
                    "}"
                )
            })

    # ── 20. Catch-All Error Leaks ─────────────────────────────────────────────
    error_leak_match = re.search(
        r'catch\s*\(\s*(?:e|err|error)\s*\)\s*\{\s*(?:return|res\.send|res\.json|Response\.json)\s*\([^;]*\b(?:e|err|error)\b[^;]*\)\s*;?\s*\}',
        code
    )
    if error_leak_match:
        findings.append({
            "id": "catch_all_error_leak",
            "name": "Raw Error Returned to Client (Information Leak)",
            "severity": "medium",
            "category": "Information Exposure",
            "technical": (
                "A try/catch block returns the raw error object (or its message) directly to the client. "
                "This can leak internal stack traces, database schema details, or file paths."
            ),
            "business": (
                "Returning raw errors gives attackers detailed information about your internal system "
                "(e.g., 'table users does not exist', 'cannot connect to 10.0.0.5'). "
                "Always return generic error messages to the client and log the real error server-side."
            ),
            "evidence": error_leak_match.group(0)[:80],
            "fix": (
                "// WRONG:\n"
                "// catch (e) { return Response.json({ error: e.message }) }\n\n"
                "// RIGHT:\n"
                "catch (e) {\n"
                "  console.error(e); // Log securely on server\n"
                "  return Response.json({ error: 'Internal server error' }, { status: 500 });\n"
                "}"
            )
        })

    # ── 21. SSRF (Server-Side Request Forgery) ────────────────────────────────
    ssrf_fetch_patterns = [
        r'(?:fetch|axios\.get|axios\.post|requests\.get|requests\.post|http\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)',
        r'(?:fetch|axios\.get|axios\.post|requests\.get|requests\.post)\s*\(\s*`[^`]*\$\{(?:req|request|params|query|body)',
    ]
    ssrf_match = next((re.search(p, code, re.IGNORECASE) for p in ssrf_fetch_patterns if re.search(p, code, re.IGNORECASE)), None)
    if ssrf_match:
        findings.append({
            "id": "ssrf_request_forgery",
            "name": "Server-Side Request Forgery (SSRF) Risk with User URL",
            "severity": "critical",
            "category": "Server-Side Request Forgery (SSRF)",
            "technical": (
                "An outgoing HTTP request (fetch/axios/requests) uses a user-supplied URL or parameters. "
                "Without strict domain allowlisting and internal IP blocking, attackers can force your server "
                "to query internal services (127.0.0.1, AWS cloud metadata 169.254.169.254, internal databases)."
            ),
            "business": (
                "SSRF can expose your cloud provider credentials, private internal APIs, and database instances. "
                "Capital One's massive breach was an SSRF vulnerability that leaked 100 million records. "
                "Always validate URLs against a strict whitelist and block internal/private IP ranges."
            ),
            "evidence": ssrf_match.group(0)[:80],
            "fix": (
                "// SAFE — Validate against allowed hosts & reject private IPs:\n"
                "const parsed = new URL(userUrl);\n"
                "const ALLOWED_DOMAINS = ['api.example.com', 'cdn.trusted.com'];\n"
                "if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {\n"
                "  return Response.json({ error: 'Untrusted domain' }, { status: 400 });\n"
                "}"
            )
        })

    # ── 22. Path Traversal / Arbitrary File Read ──────────────────────────────
    path_traversal_patterns = [
        r'(?:fs\.readFile|fs\.readFileSync|fs\.createReadStream)\s*\([^)]*(?:req\.|params\.|query\.|body\.)',
        r'path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)',
        r'open\s*\(\s*f?["\'][^"\']*(?:\{req|\{params|\{query|\{body|filename)',
    ]
    path_match = next((re.search(p, code, re.IGNORECASE) for p in path_traversal_patterns if re.search(p, code, re.IGNORECASE)), None)
    if path_match:
        findings.append({
            "id": "path_traversal_file_read",
            "name": "Path Traversal Risk in File Operation (CWE-22)",
            "severity": "critical",
            "category": "Path Traversal",
            "technical": (
                "A file system operation (fs.readFile / open) constructs paths using user input. "
                "An attacker can pass '../' sequences (e.g. '../../etc/passwd' or '../../.env') to access "
                "arbitrary files outside the intended directory."
            ),
            "business": (
                "Path traversal lets attackers download your .env secrets, database backups, source code, "
                "or system configuration files directly from your production server."
            ),
            "evidence": path_match.group(0)[:80],
            "fix": (
                "// SAFE — Use path.basename or resolve within a safe root directory:\n"
                "import path from 'path';\n"
                "const safeFilename = path.basename(req.query.file); // Strips all '../' paths\n"
                "const fullPath = path.resolve(UPLOADS_DIR, safeFilename);\n"
                "if (!fullPath.startsWith(UPLOADS_DIR)) throw new Error('Access denied');"
            )
        })

    # ── 23. Mass Assignment / Privilege Escalation ────────────────────────────
    mass_assignment_patterns = [
        r'(?:User|Account|Profile|Member)\.(?:create|update|insert)\s*\(\s*req\.body\s*\)',
        r'prisma\.(?:user|account)\.(?:create|update)\s*\(\s*\{\s*data\s*:\s*req\.body\s*\}',
        r'Object\.assign\s*\(\s*(?:user|account)\s*,\s*req\.body\s*\)',
    ]
    mass_match = next((re.search(p, code, re.IGNORECASE) for p in mass_assignment_patterns if re.search(p, code, re.IGNORECASE)), None)
    if mass_match:
        findings.append({
            "id": "mass_assignment_risk",
            "name": "Mass Assignment Vulnerability in Model Creation/Update (CWE-915)",
            "severity": "high",
            "category": "Mass Assignment",
            "technical": (
                "Directly passing req.body into database insert/update methods without field whitelisting. "
                "Clients can inject unexpected fields like 'role': 'admin', 'is_verified': true, or 'balance': 99999."
            ),
            "business": (
                "Privilege escalation allows regular users to grant themselves administrator rights "
                "or modify restricted financial fields without authorization. Always use strict DTO/Zod pick lists."
            ),
            "evidence": mass_match.group(0)[:80],
            "fix": (
                "// SAFE — Whitelist only allowed fields:\n"
                "const { name, email, bio } = req.body;\n"
                "await User.update({ name, email, bio }, { where: { id: req.user.id } });"
            )
        })

    # ── 24. NoSQL / MongoDB Operator Injection ────────────────────────────────
    nosql_patterns = [
        r'(?:User|Account)\.find(?:One)?\s*\(\s*(?:req\.body|req\.query)\s*\)',
        r'password\s*:\s*req\.body\.password',
        r'collection\.(?:find|findOne)\s*\(\s*req\.body\s*\)',
    ]
    nosql_match = next((re.search(p, code, re.IGNORECASE) for p in nosql_patterns if re.search(p, code, re.IGNORECASE)), None)
    if nosql_match:
        findings.append({
            "id": "nosql_injection_risk",
            "name": "NoSQL / MongoDB Operator Injection Risk (CWE-943)",
            "severity": "critical",
            "category": "NoSQL Injection",
            "technical": (
                "Passing unvalidated request bodies directly to MongoDB queries allows operators like $gt, $ne, $regex. "
                "For example, sending { password: { '$gt': '' } } can bypass authentication without knowing the password."
            ),
            "business": (
                "NoSQL injection allows unauthorized authentication bypass and mass database extraction. "
                "Sanitize query objects with mongo-sanitize or require string type validation via Zod."
            ),
            "evidence": nosql_match.group(0)[:80],
            "fix": (
                "// Install mongo-sanitize or validate with Zod:\n"
                "import sanitize from 'mongo-sanitize';\n"
                "const cleanBody = sanitize(req.body);\n"
                "// Ensure password is strictly a string:\n"
                "if (typeof req.body.password !== 'string') return res.status(400).send('Invalid');"
            )
        })

    # ── 25. Insecure Deserialization (pickle / PyYAML / serialize-js) ──────────
    deser_patterns = [
        r'pickle\.loads?\s*\(',
        r'yaml\.load\s*\([^,]+(?:\)|,\s*Loader\s*=\s*(?!yaml\.SafeLoader|SafeLoader))',
        r'unserialize\s*\(',
    ]
    deser_match = next((re.search(p, code, re.IGNORECASE) for p in deser_patterns if re.search(p, code, re.IGNORECASE)), None)
    if deser_match:
        findings.append({
            "id": "insecure_deserialization",
            "name": "Insecure Deserialization Detected — Remote Code Execution Risk (CWE-502)",
            "severity": "critical",
            "category": "Insecure Deserialization",
            "technical": (
                "Using unsafe deserializers (pickle.loads or yaml.load without SafeLoader). "
                "Crafted serialized payloads can execute arbitrary system commands during deserialization."
            ),
            "business": (
                "Insecure deserialization is a critical risk leading directly to Remote Code Execution (RCE) "
                "and full server compromise. Always use JSON or yaml.safe_load."
            ),
            "evidence": deser_match.group(0)[:80],
            "fix": (
                "# Python — Always use safe alternatives:\n"
                "# WRONG: yaml.load(data) or pickle.loads(data)\n"
                "# RIGHT: yaml.safe_load(data) or json.loads(data)"
            )
        })

    # ── 26. Disabled SSL / TLS Certificate Verification ───────────────────────
    ssl_disabled_patterns = [
        r'verify\s*=\s*False',
        r'rejectUnauthorized\s*:\s*false',
        r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]0[\'"]',
        r'check_hostname\s*=\s*False',
    ]
    ssl_match = next((re.search(p, code, re.IGNORECASE) for p in ssl_disabled_patterns if re.search(p, code, re.IGNORECASE)), None)
    if ssl_match:
        findings.append({
            "id": "disabled_ssl_verification",
            "name": "TLS/SSL Certificate Verification Disabled (CWE-295)",
            "severity": "critical",
            "category": "Insecure Cryptography",
            "technical": (
                "TLS certificate verification explicitly disabled via verify=False or rejectUnauthorized: false. "
                "Connections can be intercepted and modified via Man-in-the-Middle (MITM) attacks."
            ),
            "business": (
                "Attackers on the same network or upstream proxies can decrypt API keys, passwords, "
                "and user sessions in transit. Never disable TLS verification in production code."
            ),
            "evidence": ssl_match.group(0)[:80],
            "fix": (
                "// Remove verify=False or rejectUnauthorized: false:\n"
                "// Pass proper CA certificates if connecting to private servers instead of disabling validation."
            )
        })

    # ── 27. Production Debug Mode Left Enabled ────────────────────────────────
    debug_mode_patterns = [
        r'app\.run\s*\([^)]*debug\s*=\s*True',
        r'app\.debug\s*=\s*True',
        r'DEBUG\s*=\s*True',
    ]
    debug_match = next((re.search(p, code) for p in debug_mode_patterns if re.search(p, code)), None)
    if debug_match:
        findings.append({
            "id": "production_debug_enabled",
            "name": "Debug Mode Hardcoded as Enabled (CWE-489)",
            "severity": "high",
            "category": "Security Misconfiguration",
            "technical": (
                "Application framework debug mode (Flask/FastAPI/Django) is hardcoded to True. "
                "Debug modes expose interactive web consoles, complete stack traces, and local variable inspection."
            ),
            "business": (
                "Flask's Werkzeug debug console includes an interactive Python terminal that lets visitors "
                "run arbitrary shell code directly from their browser window."
            ),
            "evidence": debug_match.group(0)[:80],
            "fix": (
                "# Read debug state from environment variables with False as fallback:\n"
                "import os\n"
                "DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'\n"
                "app.run(debug=DEBUG)"
            )
        })

    # ── 28. Insecure Token Storage in LocalStorage ───────────────────────────
    localstorage_auth_patterns = [
        r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|access_token|sessionId|refreshToken)["\']',
        r'sessionStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|access_token)["\']',
    ]
    ls_match = next((re.search(p, code, re.IGNORECASE) for p in localstorage_auth_patterns if re.search(p, code, re.IGNORECASE)), None)
    if ls_match:
        findings.append({
            "id": "localstorage_auth_tokens",
            "name": "Authentication Token Stored in localStorage — XSS Vulnerable (CWE-312)",
            "severity": "medium",
            "category": "Insecure Storage",
            "technical": (
                "Auth tokens (JWT, access_token) stored in browser localStorage or sessionStorage. "
                "localStorage is accessible to any JavaScript running on the page, meaning any XSS vulnerability "
                "results in complete, silent token theft."
            ),
            "business": (
                "Attackers using third-party script compromise (supply chain attack) or minor XSS can instantly "
                "steal user sessions. Use HttpOnly, Secure, SameSite cookies instead."
            ),
            "evidence": ls_match.group(0)[:80],
            "fix": (
                "// Set token via server response Set-Cookie header:\n"
                "res.cookie('token', jwt, {\n"
                "  httpOnly: true,\n"
                "  secure: process.env.NODE_ENV === 'production',\n"
                "  sameSite: 'lax',\n"
                "});"
            )
        })

    # ── 29. Open Redirect Vulnerability ───────────────────────────────────────
    open_redirect_patterns = [
        r'res\.redirect\s*\(\s*(?:req\.query|req\.body|params)\.(?:url|next|redirect|target|to)',
        r'redirect\s*\(\s*searchParams\.get\s*\(\s*["\'](?:next|url|redirect)["\']',
        r'window\.location(?:\.href)?\s*=\s*(?:urlParams|searchParams|params)',
    ]
    redirect_match = next((re.search(p, code, re.IGNORECASE) for p in open_redirect_patterns if re.search(p, code, re.IGNORECASE)), None)
    if redirect_match:
        findings.append({
            "id": "open_redirect_vulnerability",
            "name": "Open Redirect with User-Controlled Parameter (CWE-601)",
            "severity": "medium",
            "category": "Open Redirect",
            "technical": (
                "Application performs a redirect using a destination parameter provided by the user without validation. "
                "Attackers can construct links like 'https://your-site.com/login?next=https://evil-phishing.com'."
            ),
            "business": (
                "Open redirects trick users into believing they are visiting your legitimate trusted site, "
                "before seamlessly forwarding them to credential harvesting phishing domains."
            ),
            "evidence": redirect_match.group(0)[:80],
            "fix": (
                "// SAFE — Only allow relative paths:\n"
                "const nextUrl = req.query.next || '/dashboard';\n"
                "if (!nextUrl.startsWith('/') || nextUrl.startsWith('//')) {\n"
                "  return res.redirect('/dashboard');\n"
                "}\n"
                "res.redirect(nextUrl);"
            )
        })

    # ── 30. ReDoS (Regular Expression Denial of Service) ──────────────────────
    redos_patterns = [
        r'new\s+RegExp\s*\(\s*(?:req\.|request\.|query\.|body\.|params\.)',
        r're\.compile\s*\(\s*(?:request\.|req\.|params\.)',
    ]
    redos_match = next((re.search(p, code, re.IGNORECASE) for p in redos_patterns if re.search(p, code, re.IGNORECASE)), None)
    if redos_match:
        findings.append({
            "id": "redos_user_pattern",
            "name": "Dynamic Regex Compilation from User Input — ReDoS Risk (CWE-1333)",
            "severity": "high",
            "category": "Denial of Service",
            "technical": (
                "Constructing RegExp instances directly from user input without escaping or length limits. "
                "Attackers can submit catastrophic backtracking patterns (e.g. (a+)+$) that lock up the NodeJS event loop "
                "or Python worker thread at 100% CPU."
            ),
            "business": (
                "A single request with a malicious regex pattern can hang your entire Node.js single-threaded server, "
                "causing a complete Denial of Service (DoS) for all users."
            ),
            "evidence": redos_match.group(0)[:80],
            "fix": (
                "// SAFE — Escape regex special characters or use plain string search:\n"
                "function escapeRegex(string) {\n"
                "  return string.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');\n"
                "}\n"
                "const safeRegex = new RegExp(escapeRegex(userInput), 'i');"
            )
        })
        findings.append({
            "id": "api_looks_ok",
            "name": "No Obvious API Route Issues Detected",
            "severity": "info",
            "category": "API Route Analysis",
            "technical": "Auth check, rate limiting, and input patterns look reasonable.",
            "business": "Your API route looks reasonable at a basic automated review level.",
            "evidence": "Passed all automated checks",
            "fix": None
        })

    logger.info(f"API route analysis complete — {len(findings)} findings")
    return findings