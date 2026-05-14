This project is a fast-reaction vulnerability notifier for SUSE.

It works by:
    1. Subscribing to RSS feeds of the most important websites where
       supply chain attacks (compromised libraries or other components)
       are most likely to be reported
    2. Analyzing the articles using an external LLM, called via a
       configurable (YAML config file) command. By default, that is Gemini
       CLI in non-interactive modes to see whether they talk about a supply
       chain attack, to extract the affected library name, version, and time
       window in which it was compromised and what files were compromised
       and whether there is any malicious payload that appears during build.
    3. If a compromise is found, checks a compromise database (ideally a
       simple JSON file until a more scalable solution is needed) and if
       it is duplicate, ignores it and the work is done.
    4. If not duplicate, then it adds it to the database and runs searches
       on the openSUSE Build Service (using 'osc') to find whether any of
       the projects hosted there contain the package.
    5. If those packages are found, then it proceeds to analyzing their
       changelogs to see whether they have been updated within the
       compromised timeframe and/or version. It also checks out the package
       to see if the malicious files are present. If yes, then it reports
       the findings (initially via STDOUT, eventually via email/slack).
