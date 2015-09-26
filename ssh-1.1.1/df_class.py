#!/usr/bin/env python
# _*_ coding:utf-8 _*_
from __future__ import with_statement
import ConfigParser,time
import os,sys,traceback
import getpass,re,hashlib,commands
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from colorama import init, Fore, Back, Style
class Universal():
    if os.name == "nt":
        init(autoreset=True)
        def __init__(self):
            pass
        def ingreen(self,s): 
            return  Fore.LIGHTGREEN_EX +'%s' % s 
        def indgreen(self,s): 
             return  Fore.LIGHTGREEN_EX +'%s' % s 
        def inyellow(self,s): 
             return  Fore.YELLOW +'%s' % s 
        def inblue(self,s):
            return  Fore.LIGHTCYAN_EX +'%s' % s 
        def inred(self,s): 
            return  Fore.LIGHTRED_EX +'%s' % s 
    else:
        
        def __init__(self):
            pass
        def ingreen(self,s): 
            return"%s[30;32;2m%s%s[0m"%(chr(27), s, chr(27)) 
        def indgreen(self,s): 
            return"%s[30;35;2m%s%s[0m"%(chr(27), s, chr(27))
        def inyellow(self,s): 
            return"%s[30;33;1m%s%s[0m"%(chr(27), s, chr(27))
        def inblue(self,s):
            return "%s[30;34;1m%s%s[0m"%(chr(27), s, chr(27))
        def inred(self,s): 
            return"%s[30;31;2m%s%s[0m"%(chr(27), s, chr(27)) 
    #定义一个迭代文件的方法
    def read_file(self,fpath): 
        """定义一个迭代文件的方法
        """
        BLOCK_SIZE = 1024 
        with open(fpath, 'rb') as f: 
            while True: 
                block = f.read(BLOCK_SIZE) 
                if block: 
                    yield block 
                else: 
                    return   
    def md5sum(self,fname):
        """ 计算文件的MD5值
        """       
        m = hashlib.md5()
        if isinstance(fname, basestring) and os.path.exists(fname):
            #with open(fname, "rb") as fh:
            for chunk in self.read_file(fname):
                m.update(chunk)
        #上传的文件缓存或已打开的文件流
        elif fname.__class__.__name__ in ["StringIO", "StringO"] or isinstance(fname, file):
            for chunk in self.read_fiel(fname):
                m.update(chunk)
        else:
            return ""
        return m.hexdigest()
    def dir_walk(self,fpath):
        list_return = []
        counter=1
        for path1,dir1,filename in sorted(os.walk('%s' % fpath)):
            for file1 in sorted(filename):
                l = os.path.join(file1)
                list_return.append(str(counter)+" "+l)
                counter+=1
        return list_return
    #这是一个格式化输出内容的方法
    def printindex(self,*content):
        sing,sing1,sing2,sentence,maxsent=self.inred("+"),self.ingreen("-"),self.ingreen("|"),[],0
        for i in xrange(len(content)):
            sentence.append(content[i])
            if maxsent <=len(content[i]):
                maxsent=len(content[i])
        screen_width=40
        text_width=maxsent
        box_width=text_width+6
        left_margin=(screen_width-box_width)//2
        print ' ' *left_margin + sing + sing1 *(box_width-4) + sing
        print ' ' *left_margin + sing2 + ' ' *(text_width+1) +' ' + sing2
        for i in xrange(len(content)):
            print ' ' * left_margin + sing2 + ' ' + sentence[i]  + ' '*(maxsent-len(sentence[i])+1)  + sing2
        print ' ' * left_margin + sing2 + ' ' *(text_width+1) + " "    + sing2
        print ' ' * left_margin + sing + sing1 *(box_width-4)  + sing
    def encrypt(self,text):
        self.key = "@w#hj%7(3uio123h"
        self.mode = AES.MODE_CBC
        #这里密钥key 长度必须为16（AES-128）,
        #24（AES-192）,或者32 （AES-256）Bytes 长度
        #目前AES-128 足够目前使用 
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串转化为16进制字符串
        length = 16
        count = len(text)
        if count < length:
            add = (length-count)
            #\0 backspace
            text = text + ('\0' * add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)
    def decrypt(self,text):
        self.key = "@w#hj%7(3uio123h"
        self.mode = AES.MODE_CBC
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        plain_text  = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')
    def allcommands(self):
        ''' 获取远程机器上的所有命令列表 '''
        stdin,stdout,stderr = ssh.exec_command("for c in $(echo $PATH |sed 's/:/ /g');do ls $c;done")
        return stdout.read().strip().split('\n')
    def alllocalcommands(self):
        """获取本机上的所有命令列表"""
        local_cmd=commands.getstatusoutput("for c in $(echo $PATH |sed 's/:/ /g');do ls $c;done")
        return local_cmd[1].strip().split('\n')
    def allpath(self,path=''):
        '''获取远程机器上某路径下的所有下的所有文件和目录'''
        rpath = os.path.join(curr_pwd,path)
        stdin,stdout,stderr = ssh.exec_command("ls -p %s" % rpath)
        return stdout.read().strip().split()
    def alllocalpath(self,path=''):
        '''获取本机某路径下的所有文件和目录'''
        result = []
        if not path: path = '.'
        for f in os.listdir(path):
            qf = os.path.join(path,f)
            if os.path.isdir(qf):
                result.append(f+os.sep)
            else:
                result.append(f)
        return result 
