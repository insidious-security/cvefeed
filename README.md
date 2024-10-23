# CVEFEED

This program pulls the latest CVE data directly from an RSS feed, parsing and organizing it into a sleek list. Browse vulnerabilities in style with a dynamic table of CVEs, and dive deep into each one for a full description and publication details—all within your console. Effortless security insights, one CVE at a time!
Check out the [demo video](assets/cvefeed.mp4) to see it in action.



## How to use:
### 1. Create a Virtual Environment:   
It's good practice to use a virtual environment for Python projects to keep dependencies isolated.
```bash
$ python -m venv cve
$ source cve/bin/activate
```

### 2. Install Dependencies:
With the virtual environment activated, install the required Python packages:
```bash
$ pip install rich requests
```

### Run the program:
```bash
$ python cvefeed.py
```
