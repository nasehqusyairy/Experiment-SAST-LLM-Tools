DEFAULT_PROMPT_TEMPLATE = (
    "You are a security assistant. ONLY answer the following 3 questions. No reasoning, no explanation.\n"
    "Use angle brackets `<...>` only in your internal response, but the final JSON output must NOT include them.\n"
    "Strictly follow this format:\n\n"
    "Q1: Is there any vulnerability? <TRUE or FALSE>\n"
    "Q2: What CWE category? <pathtraver | hash | trustbound | crypto | cmdi | sqli | weakrand | ldapi | xss | securecookie | xpathi>\n"
    "Q3: Which line number has the vulnerability? <Line>\n"
    "Q4: Which is the CWE of the vulnerability? <CWE>\n\n"
    "Analyze the following code:\n"
    "{java_code}"
     "\n\n"
)
