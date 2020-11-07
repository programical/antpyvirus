#!/usr/bin/env python3
# antpyvirus by programical (licensed under The Unlicense)
# https://github.com/programical/antpyvirus


import socket, os, hashlib, threading, tkinter as tk


class Antpyvirus:
    def __init__(self):
        self.hashes = {} # path:hash
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
            activeforeground = '#44FF44',
        )
        self.scanButton.pack(side = tk.LEFT)
        # result field
        self.resultField = tk.Text(
            self.window,
            bd = 0,
            highlightthickness = 0,
            bg = '#111111',
            fg = '#FFFFFF'
        )
        self.resultField.pack(side = tk.TOP, fill = tk.BOTH, expand = tk.YES)
        self.resultField.config(state = tk.DISABLED)
        # begin
        self.window.mainloop()

    def startScan(self):
        threading.Thread(target = self.scan).start()

    def scan(self):
        # disable interface
        self.scanButton.config(state = tk.DISABLED)
        self.scanPathEntry.config(state = tk.DISABLED)
        self.resultField.config(state = tk.NORMAL)
        self.resultField.delete(1.0, tk.END)
        self.resultField.config(state = tk.DISABLED)

        # hash
        scanTarget = self.scanPathEntry.get()
        self.hashes = {}
        self.output('Scanning: ' + scanTarget + '\nHashing...\n')
        if os.path.isdir(scanTarget):
            self.analyzeDir(scanTarget)
        elif os.path.isfile(scanTarget):
            self.addHash(scanTarget)
        else:
            self.output('Invalid path: ' + scanTarget + '\n')

        # compare with database
        self.output('Sending for analysis...\n')
        if self.hashes != {}:
            try:
                self.checkHashes()
            except Exception as err:
                self.output('Analysis error: ' + str(err) + '\n')
        else:
            self.output('Nothing to do.\n')
        self.output('Done.\n')
        # enable interface
        self.scanButton.config(state = tk.NORMAL)
        self.scanPathEntry.config(state = tk.NORMAL)

    def analyzeDir(self, dir: str):
        try:
            # recursive scan
            for child in os.listdir(dir):
                whole = dir + '/' + child
                if os.path.isdir(whole):
                    self.analyzeDir(whole)
                elif os.path.isfile(whole):
                    self.addHash(whole)
                else:
                    self.output('Not found: ' + whole + '\n')
        except Exception as err:
            self.output('Scanning error: ' + str(err) + '\n')

    def addHash(self, path: str):
        try:
            with open(path, 'rb') as file:
                self.hashes[path] = hashlib.md5(file.read()).hexdigest()
        except Exception as err:
            self.output('Hashing error: ' + str(err) + '\n')

    def checkHashes(self):
        # format hashes to expected format
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
                response += data
                if not data:
                    break
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
                    self.output('Threat (' + score + '%): ' + file + '\n')

    def output(self, text: str):
        self.resultField.config(state = tk.NORMAL)
        self.resultField.insert(tk.END, text)
        self.resultField.config(state = tk.DISABLED)


def main():
    Antpyvirus()


if __name__ == '__main__':
    main()
