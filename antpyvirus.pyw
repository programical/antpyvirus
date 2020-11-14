#!/usr/bin/env python3
# antpyvirus by programical (licensed under The Unlicense)
# https://github.com/programical/antpyvirus


import socket, os, hashlib, threading, tkinter as tk


# writes to the log file
class Logger:
    logFile = os.path.dirname(os.path.abspath(__file__)) + '/log/scan.log'

    def log(text: str):
        with open(Logger.logFile, 'a') as file:
            file.write(text)

    def clear():
        open(Logger.logFile, 'w').close()


# scans, hashes and analyzes a tree/file for threats
class Scanner:
    def __init__(self):
        self.hashes = {} # path:hash
        self.notScanned = 0 # n of files and dirs that caused errors
        self.threats = {} # path:percentage(float)

    # recursively scans tree
    def recursiveScan(self, path: str):
        try:
            if os.path.isdir(path):
                for child in os.listdir(path):
                    self.recursiveScan(path + '/' + child)
            elif os.path.isfile(path):
                self.addHash(path)
            else:
                Logger.log('Cannot access: ' + path + '\n')
                self.notScanned += 1
        except Exception as err:
            Logger.log('Scanning error: ' + str(err) + '\n')
            self.notScanned += 1

    # stores hashes for later analysis
    def addHash(self, path: str):
        # FIXME: crazy ram usage, obviously.
        # send in smaller batches? use local storage instead of RAM?
        try:
            with open(path, 'rb') as file:
                self.hashes[path] = hashlib.md5(file.read()).hexdigest()
        except Exception as err:
            Logger.log('Hashing error: ' + str(err) + '\n')
            self.notScanned += 1

    def scan(self, target: str, callback: callable):
        # clear logfile
        Logger.clear()

        # format target
        if len(target) > 1 and target.endswith('/'):
            target = target[:-1]

        # hash files
        self.hashes = {}
        self.notScanned = 0
        self.threats = {}
        Logger.log('Scanning: ' + target + '\nHashing...\n')
        if os.path.isdir(target) or os.path.isfile(target):
            self.recursiveScan(target)
        else:
            Logger.log('Invalid path: ' + target + '\n')

        # compare with database
        Logger.log('Sending for analysis...\n')
        if self.hashes != {}:
            # change hashes to expected format
            request = 'begin\n'
            for key in self.hashes:
                request += self.hashes[key] + '\n'
            request += 'end'

            # setup socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            # send hashes
            sock.connect(('hash.cymru.com', 43))
            sock.send(request.encode())

            # receive response
            response = b''
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    else:
                        response += data
                except socket.timeout:
                    break

            sock.close()

            # parse response
            for line in response.decode().split('\n')[2:]:
                if line.strip() != '':
                    hash = line.split(' ')[0]
                    file = ''
                    for path in self.hashes:
                        if self.hashes[path] == hash:
                            file = path
                            break
                    score = line.split(' ')[2]
                    if score != 'NO_DATA':
                        Logger.log('Threat (' + score + '%): ' + file + '\n')
                        self.threats[file] = float(score)
        else:
            Logger.log('Nothing to do.\n')

        # finish
        Logger.log('Not scanned: ' + str(self.notScanned) + ' files.\nDone.\n')
        callback(self.threats, self.notScanned)


# controls the interface, calls the shots
class App:
    def __init__(self):
        # window
        self.window = tk.Tk()
        self.window.wm_title('antpyvirus')
        self.window.minsize(320, 180)
        self.window.geometry('800x450')
        # input frame
        inputFrame = tk.Frame(
            self.window,
            bg = '#222222'
        )
        inputFrame.pack(side = tk.TOP, fill = tk.BOTH)
        # label
        tk.Label(
            inputFrame,
            text = ' Path: ',
            bg = '#222222',
            fg = '#FFFFFF'
        ).pack(side = tk.LEFT)
        # path entry
        self.scanPathEntry = tk.Entry(
            inputFrame,
            bd = 0,
            highlightthickness = 0,
            bg = '#101010',
            fg = '#FFFFFF',
            disabledbackground = '#111111'
        )
        self.scanPathEntry.pack(side = tk.LEFT, fill = tk.X, expand = tk.YES)
        # scan button
        self.scanButton = tk.Button(
            inputFrame,
            command = self.startScan,
            text = 'Scan',
            bd = 0,
            highlightthickness = 0,
            bg = '#222222',
            fg = '#FFFFFF',
            activebackground = '#222222',
            activeforeground = '#FFFF44',
        )
        self.scanButton.pack(side = tk.LEFT)
        # result field
        self.resultField = tk.Text(
            self.window,
            bd = 0,
            highlightthickness = 0,
            bg = '#111111',
            fg = '#FFFF00'
        )
        self.resultField.pack(side = tk.TOP, fill = tk.BOTH, expand = tk.YES)
        self.resultField.config(state = tk.DISABLED)
        # begin
        self.window.mainloop()

    def startScan(self):
        # prevent starting multiple scans at once
        self.scanButton.config(state = tk.DISABLED)
        self.scanPathEntry.config(state = tk.DISABLED)
        # print new scan
        self.resultField.config(state = tk.NORMAL)
        self.resultField.delete(1.0, tk.END)
        self.resultField.insert(tk.END, 'Scanning...\n')
        self.resultField.config(state = tk.DISABLED)
        # spawn scan thread
        threading.Thread(
            target = Scanner().scan,
            args = (self.scanPathEntry.get(), self.endScan)
        ).start()

    def endScan(self, threats: dict, notScanned: int):
        # allow scanning again
        self.scanButton.config(state = tk.NORMAL)
        self.scanPathEntry.config(state = tk.NORMAL)
        # print results
        self.resultField.config(state = tk.NORMAL)
        self.resultField.delete(1.0, tk.END)
        self.resultField.insert(tk.END, str(notScanned) + ' not scanned.\n')
        if len(threats) > 0:
            for path in threats:
                self.resultField.insert(
                    tk.END,
                    '(' + threats[path] + '%) ' + path + '\n'
                )
        else:
            self.resultField.insert(tk.END, 'No threats found.\n')

        self.resultField.config(state = tk.DISABLED)


def main():
    App()


if __name__ == '__main__':
    main()
