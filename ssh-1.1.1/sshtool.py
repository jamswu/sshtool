#!/usr/bin/env python 
# _*_ coding:utf-8 _*_
import df_class,os,sys,cPickle,re
import paramiko,socket,threading,Queue
import interactive,time,getpass,hashlib
import readline,logging

#from progressbar import Bar,BouncingBar,Counter,ETA,FileTransferSpeed, FormatLabel,Percentage,ProgressBar,ReverseBar,RotatingMarker,SimpleProgress,Timer
class Sshclient(df_class.Universal):
    ok_count={}
    error_count={}
    lock=threading.Lock()
    sudo_cmd=re.compile(r'^sudo ')
    sudo_str=re.compile(r'^\[sudo\] password for')
    def ssh2_conn(self,ip,username,port,passwd,cmd=""):
        self.connections=[]
        self.hosts=[]
        self.conn_queue=[]
       # self.lock.acquire()
        try:
            ssh2=paramiko.SSHClient() #建立连接
            #缺失host_knows时的处理方法
            ssh2.load_system_host_keys()
            ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            passwd1=self.decrypt(passwd)
            ip,port,username=self.decrypt(ip),int(self.decrypt(port)),self.decrypt(username)
            ssh2.connect(ip,port,username,passwd1,timeout=10)
            print self.inblue("connect %s %s OK") % (ip,"-"*35)
            myconn=(ip,ssh2)
            myqueue=Queue.Queue()
            mystdout=Queue.Queue()
            #myhostname=Queue.Queue()
            myqueue.put(myconn)
            self.ok_count[ip]=[port,username,passwd]
            self.connections.append(ssh2)
            self.hosts.append(ip)
            time.sleep(2)
            if cmd:
               # self.lock.acquire()
     #           host,conn=ip,ssh2
                conn_queue=myqueue.get_nowait()
                host,conn=conn_queue[0],conn_queue[1]
                #print conn_queue
               # print  "="*35+host+"="*35
               # stdin,stdout,stderr=conn.exec_command("hostname")
                #myhostname.put(stdout)
                #time.sleep(2)
               # my_hostname=stdout.read().strip("\n")
                if self.sudo_cmd.findall(cmd): 
                    stdin,stdout,stderr=conn.exec_command(cmd, get_pty=True)
                    stdin.write("%s\n" % passwd1)
                    mystdout.put(stdout)
                    #time.sleep(0.5)
                    stdout=mystdout.get_nowait()
                    returnvalue=stdout.channel.recv_exit_status()
                    #print "hello"+repr(returnvalue)
                    self.lock.acquire()
                    a=0
                    print  "="*30+host+"="*30
                    for line in stderr.readlines():
                        print " "*20+self.inred(line)
                    for line in stdout.readlines():
                        if line:
                            if a<2:
                                if line.strip('\r\n') == passwd1 or self.sudo_str.findall(line):
                                    a+=1
                                else:
                                    print self.inyellow(line)
                            else:
                                print self.inyellow(line)
                    self.lock.release()
                else:
                    stdin,stdout,stderr=conn.exec_command(cmd)
                    mystdout.put(stdout)
                    #time.sleep(0.5)
                    stdout=mystdout.get_nowait()
                    returnvalue=stdout.channel.recv_exit_status()
                    #print "hello"+repr(returnvalue)
                    self.lock.acquire()
                    print  "="*30+host+"="*30
                    for line in stderr.readlines():
                        print " "*20+self.inred(line)
                    for line in stdout.readlines():
                        print self.inyellow(line)
                    self.lock.release()
            time.sleep(2)      
        except paramiko.AuthenticationException,e:
            e=str(e)
            print self.inred("connect %s %s Error") % (ip,"-"*35),self.indgreen(e)
            self.error_count[ip]=[port,username,passwd]
        except paramiko.ssh_exception.AuthenticationException,e:
            print self.inred("change root %s %s Error") % (ip,"-"*35),self.indgreen(str(e))
        except socket.error,er:
            er=str(er)
            print self.inred("connect %s %s Error") % (ip,"-"*35),self.inyellow(er)
            self.error_count[ip]=[port,username,passwd]
        except paramiko.ssh_exception.SSHException:
            print self.inred("connect %s %s Error") % (ip,"-"*35),self.indgreen("Connection reset by peer")
            self.error_count[ip]=[port,username,passwd]
     #   self.lock.release()
    def multi_threading(self,dict_data,run_function,localfile="",remotepath="",cmd=""):
        data=[]
        for key,values in dict_data.iteritems():
            #@key 取出后为hostname
            port,username,passwd=values[0],values[1],values[2]
            #data.append(((),{"ip":key,"username":values[1],"passwd":values[2],"port":values[0]}))
            if localfile:
            #   if cmd:
             #      data.append(threading.Thread(target=run_function,args=(key,username,passwd,port,localfile,remotepath,cmd)))
            #   else:
               data.append(threading.Thread(target=run_function,args=(key,username,passwd,port,localfile,remotepath)))
            else:
                data.append(threading.Thread(target=run_function,args=(key,username,port,passwd,cmd)))
        for t in data:
            t.start()
        for t in data:
            t.join()
    #def example(self,file,file_size):
    #    widgets = ['working:', Percentage(), ' ', Bar(marker=RotatingMarker()),
    #               ' ', ETA(), ' ', FileTransferSpeed()]
    #    pbar = ProgressBar(widgets=widgets, maxval=100000).start()
    #    for i in xrange(10000):
    #        # do something
    #        pbar.update(10*i+1)
    #    pbar.finish()
    ##def _callback(self,a,b):
    #    sys.stdout.write('Data Transmission %10d [%3.2f%%]\r' %(a,a*100./int(b)))
    #    sys.stdout.flush()       
    def sftp(self,ip,username1,passwd,port,localfile,remotepath,cmd=""):
        n=0
        self.count1=0
        self.count=0
        self.blockSize2=0
        self.Symbol=self.Symbol_2=self.indgreen("#")
        ip,port,username1=self.decrypt(ip),int(self.decrypt(port)),self.decrypt(username1)
        #def report(blockSize1,totalSize):
        #    blockSize=blockSize1-self.blockSize2
        #    self.blockSize2=blockSize1
        #    #print blockSize,totalSize
        #    self.count+=1
        #    if blockSize != 32768:
        #        self.percent = int(((self.count-1)*32768+blockSize)*100/totalSize)
        #    else:
        #        self.percent = int(self.count*blockSize*100/totalSize)
        #    if self.count1 < self.percent and self.percent % 2 == 0:
        #        self.Symbol_2+=self.Symbol
        #    #if get_up == "get":
        #    mark1=self.ingreen('Download')
        #    #else:
        #     #   mark1=self.ingreen('UPload')
        #    if self.count1<self.percent:               
        #        sys.stdout.write("\r%d%%" % self.percent + mark1+self.Symbol_2+self.indgreen('>'),)
        #        sys.stdout.flush()
        #        self.count1=self.percent 
        try:
            #host_keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            tcpsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
            tcpsock.settimeout(5) 
            tcpsock.connect((ip,port),)
            scp= paramiko.Transport(tcpsock) 
            #scp=paramiko.Transport((ip,port))
            #print ip,port
            passwd=self.decrypt(passwd)
            scp.connect(username=username1,password=passwd)
            sftp=paramiko.SFTPClient.from_transport(scp)
            if cmd:
                sftp.get(localfile,remotepath,self)
            else:
                sftp.put(localfile,remotepath)
            #scp.close()
            print self.inblue('%s ------- ok' % ip)
        except Exception,e:
            print self.inred('%s ------error ' % ip)+str(e)
    def do_run(self,cmd=''):
        if cmd:
            for host,conn in zip(self.hosts,self.connections):
                print  "="*35+host+"="*35
                stdin,stdout,stderr=conn.exec_command(cmd)
                returnvalue=stdout.channel.recv_exit_status()
                print returnvalue,"---------------------"                
                if returnvalue != 0:
                #and returnvalue != 1:
                    #print " "*20+"Sorry,not found command'%s'!" % self.inred(cmd)
                    #continue
                    for line in stderr.readlines():
                        if line:
                            print self.inred(line)
                for line in stdout.readlines():
                    if line:
                        print self.inyellow(line)
        else:
            print 'usage:run cmd'
    def ssh_loginhost(self,ip,port,username1,passwd):
        try:
            ssh=paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            passwd=self.decrypt(passwd)
            ssh.connect(ip,port=int(port),username=username1,password=passwd)

            win_size =interactive.get_win_size()
            channel=ssh.invoke_shell(height=win_size[0], width=win_size[1])
            #建立交互式管道 
            interactive.interactive_shell(channel)  
            #关闭连接 
            channel.close() 
            ssh.close()
        except Exception,e:
            print self.inred('%s ------error ' % ip)+str(e)
class Operatinghost(df_class.Universal,Sshclient):
    def user_auth(self):
        if not os.path.exists("authuser"+"/"+"user_auth"):
            passwd=hashlib.md5("sshtool.123").hexdigest()
            data={self.encrypt("sshtool"):[0,passwd,"unlock"]}
            cPickle.dump(data,open("authuser"+"/"+"user_auth","wb"))
        while True:
            counter=0
            username=(raw_input("Login name:").strip()).lower()
            if len(username)<1:
                print self.inred("Sorry,username not empty!")
                continue
            else:
                break
        while True:                    
            if counter<3:
                loginpass=getpass.getpass("passwd:")
                if len(loginpass)<1:
                    print self.inred("Sorry,passwd not empty!")
                    continue
                data=cPickle.load(open("authuser"+"/"+"user_auth","rb"))
                if self.encrypt(username) in data:
                    loginpass=hashlib.md5(loginpass).hexdigest()
                    if data[self.encrypt(username)][1] == loginpass:
                        break
                    else:
                        print self.inred("Sorry, password error!")
                        counter+=1
                        continue
                else:
                    print self.inred("Sorry, password error!")
                    counter+=1        
                    continue
            else:
                if self.encrypt(username) in data:
                    print self.inred("I'm sorry, too many times you enter the wrong, your account %s has been locked!" % username)
                    data[self.encrypt(username)][2]="lock"
                    cPickle.dump(data,open("authuser"+"/"+"user_auth","wb"))
                else:
                    print self.inred("Sorry,Username %s does not exist or the password is wrong!" % username)
                sys.exit()
    def add_user(self):
        re_username=re.compile(r'^[a-zA-Z]\w{3,15}')
        if not os.path.exists("authuser"+"/"+"user_auth"):
            passwd=hashlib.md5("sshtool.123").hexdigest()
            data={self.encrypt("sshtool"):[0,passwd,"unlock"]}
            cPickle.dump(data,open("authuser"+"/"+"user_auth","wb"))
        while True:
            count=0 
            while True:
                username=raw_input('please input username:').strip().lower()     
                if not re_username.findall(username):
                    str1="Sorry user name must begin with a letter and can contain numbers and underscores in length between 4,15!"
                    print "%s" % self.inred(str1)
                    continue
                data = cPickle.load(open("authuser"+"/"+"user_auth","rb"))
                if self.encrypt(username) in data:
                    print "sorry,the user '%s' already exists!!!" % self.inred(username1)
                    continue
                else:
                    break
            while True:
                userpasswd=getpass.getpass('please input your passwd:')
                if len(userpasswd)< 6:
                    print "sorry,The password can not be less than %s!" % self.inred("6")
                    continue
                Repasswd=getpass.getpass('Repeat password:')
                if userpasswd == Repasswd:
                    userpasswd=hashlib.md5(userpasswd).hexdigest()
                    Manage_user=raw_input("是否将用户 '%s' 设置为管理员 'Y' 是，else 否:" % username).strip().lower() 
                    if Manage_user=="y":
                        user_level=0
                        user_status="unlock"
                    else:
                        user_level=1
                        user_status="unlock"
                    data = cPickle.load(open("authuser"+"/"+"user_auth","rb"))
                    data[self.encrypt(username)]=[user_level,userpasswd,user_status]
                    cPickle.dump(data,open("authuser"+"/"+"user_auth","wb"))
                    print self.indgreen("Congratulations! Add user Successful")
                    print 
                    break
                else:
                    print self.inred("Sorry, passwords do not match,Please re-enter!")
                    count+=1
                    if count >2:
                        break
                    continue
            if count!=3:
                userselect=raw_input("是否继续添加用户 'b' 返回，其他继续添加:").strip().lower()
                if userselect =='b':
                    break
                else:
                    continue
            else:
                break
    def user_login(self):
        try:
            self.server_list_dir="server_list" 
            if not os.path.isdir(self.server_list_dir):
                os.makedirs(self.server_list_dir)
            else:
                pass
            if not os.path.isdir("authuser"):
                os.makedirs("authuser")
            else:
                pass
            while True:
                self.printindex("1 Manage Login","2 User Login","3 Exit system")
                userselect=raw_input('Please select the services you need number(1 or 2):').strip()                
                if userselect == "1":
                    self.user_auth()
                    while True:
                        self.printindex("1 add_group","2 del_group","3 Modify the group name","4 add_host to group","5 del_host from group","6 View Group or host","7 add user","8 Back to higher")
                        user_select=raw_input('Please select the services you need number(1,2,3 or 4):').strip()  
                        if user_select=="1":
                            self.add_group()
                        elif user_select == "2":
                            self.del_group()
                        elif user_select == "3":
                            self.rename_group()
                        elif user_select == "4":
                            self.addhostto_group()
                        elif user_select == "5":
                            self.del_host()
                        elif user_select == "6":
                            while True:
                                mark_exit=0
                                self.cat_group(self.server_list_dir)
                                userselect=raw_input("Enter the group name or group number View group hosts,else back:").strip().lower()
                                if len(userselect)<1:
                                    break
                                for i in self.dir_walk(self.server_list_dir):
                                    group_number,group_name=i.split()[0],i.split()[1]
                                    if userselect == group_name or userselect==group_number:
                                        self.cat_host(group_name)
                                        user_slt=raw_input("按'Y'继续查询，其他返回上层:").strip().lower()
                                        if user_slt == "y":
                                            mark_exit=1
                                            break  #退出for 继续查询
                                        else:                                       
                                            break
                                else:
                                    break
                                if mark_exit==1:
                                    continue
                                break
                        elif user_select == "7":
                            self.add_user()
                        elif user_select == "8":
                            break
                        else:
                             print self.inred("sorry,You must select 1,2,3or 4!")
                             continue 
                elif userselect == "2":
                    self.user_auth()
                    while True:
                        self.printindex("1 Run comand","2 send/get file","3 login host","4 Back up higher")
                        userselect=raw_input('Please select the services you need number(1,2or 3):').strip()
                        if userselect =="1":
                            while True:
                                self.cat_group(self.server_list_dir)
                                userselect=raw_input("请输入要执行命令的组名或编号,其他返回:").strip().lower()
                                for i in self.dir_walk(self.server_list_dir):
                                    group_number,group_name=i.split()[0],i.split()[1]
                                    if userselect == group_name or userselect==group_number:
                                        self.cat_host(group_name)
                                        while True:
                                            user_slt=raw_input("按'B'返回，其他执行命令:").strip().lower()
                                            if user_slt == "b":
                                                break  #退出while 继续查询
                                            else:
                                                while True:                                       
                                                    user_cmd=raw_input("please input run cmd>").strip()
                                                    if len(user_cmd) >=1:
                                                        break 
                                                data = cPickle.load(open(self.server_list_dir+"/"+group_name,"rb"))
                                                data1=[]
                                                for i in data:
                                                    data1.append(self.decrypt(i))
                                                self.multi_threading(data,self.ssh2_conn,cmd=user_cmd)
                                                print "Success: %s  Error: %s" % (self.inblue(len(self.ok_count)),self.inred(len(self.error_count)))
                                                error_host=list((set(data1)-set(self.ok_count)))
                                                if error_host:
                                                    print "Error hostlist: %s" % self.ingreen(error_host)
                                                self.ok_count={}
                                                self.error_count={}
                                        break
                                else:
                                    break
                            #multi_threading()
                            #do_run()
                        elif userselect == "2":
                            while True:
                                self.printindex("1 put file to remote host ","2 get file from remotehost","3 back to higher")
                                userselect=raw_input('Please select the services you need number(1,2or 3):').strip()
                                if userselect == "1":
                                    while True:
                                        self.cat_group(self.server_list_dir)
                                        user_select=raw_input("请选择要上传到的组的组名或编号,其他返回:").strip().lower()
                                        for i in self.dir_walk(self.server_list_dir):
                                            group_number,group_name=i.split()[0],i.split()[1]
                                            if user_select == group_name or user_select==group_number:
                                                self.cat_host(group_name)
                                                user_slt=raw_input("按'Y'上传文件，其他返回:").strip().lower()
                                                if user_slt != "y":
                                                    break  #退出for 继续查询
                                                else:                                                                              
                                                    localfile=raw_input("请输入你要上传的文件:").strip()                                                
                                                    remotefilepath=raw_input("请输入你要上传文件到远程主机的路径:").strip()
                                                    data = cPickle.load(open(self.server_list_dir+"/"+group_name,"rb"))
                                                    self.multi_threading(data,self.sftp,localfile,remotefilepath)
                                        else:
                                            break
                                        break
                                elif userselect == "2":
                                    while True:
                                        get_hostname=raw_input("请输入你要下载文件的主机名或ip:").strip()
                                        gethost_dict={}
                                        for i in self.dir_walk(self.server_list_dir):
                                            mark_exit=0
                                            data=cPickle.load(open(self.server_list_dir+"/"+i.split()[1]))
                                            if get_hostname in data:
                                                getvalue=data[get_hostname]
                                                gethost_dict[get_hostname]=getvalue
                                                while True:
                                                    localfile=raw_input("请输入你要下载的文件:").strip()
                                                    if len(localfile)<2:
                                                        print self.inred("sorry,Invalid Input")
                                                        continue
                                                    break
                                                while True:
                                                    remotefilepath=raw_input("请输入你要保存到本地主机的文件路径:").strip() 
                                                    if len(remotefilepath)<2:
                                                        print self.inred("sorry,Invalid Input")
                                                        continue
                                                    break
                                                data = cPickle.load(open(self.server_list_dir+"/"+i.split()[1],"rb"))
                                                self.multi_threading(gethost_dict,self.sftp,localfile,remotefilepath,"get")
                                                break
                                        else:
                                            print self.inred("对不起主机'%s'暂未添加，请先添加主机!") % get_hostname
                                            break
                                        break
                                elif userselect =="3":
                                    break
                                else:
                                    print "Invalid selection"
                                    continue
                        elif userselect == "3":
                            while True:
                                login_host=raw_input("请输入你要登陆的主机名或ip:")
                                for i in self.dir_walk(self.server_list_dir):
                                    mark_exit=0
                                    data=cPickle.load(open(self.server_list_dir+"/"+i.split()[1]))
                                    if self.encrypt(login_host) in data:
                                        port,username,passwd=data[self.encrypt(login_host)][0],data[self.encrypt(login_host)][1],data[self.encrypt(login_host)][2]
                                        self.ssh_loginhost(login_host,self.decrypt(port),self.decrypt(username),passwd)
                                        break
                                else:
                                    print self.inred("对不起主机'%s'暂未添加，请先添加主机!") % login_host
                                    break
                                break                                                                                        
                        elif userselect == "4":
                            break
                        else:
                            print self.inred("sorry,You must select 1,2,3or 4!")                  
                            continue  
                elif userselect == "3":
                    sys.exit()
                else:
                    print self.inred("sorry,You must select 1 or 2!")
        except (KeyboardInterrupt,EOFError):  #异常捕捉,
            print "\n"+"Welcome once again to our system!"
            sys.exit()
    def cat_group(self,server_listdir):
        print 
        print self.inyellow("This is my current grouping:")
        print 
        print self.indgreen(u"—")*80
        for  i in self.dir_walk(server_listdir):
            quantity=str(len(cPickle.load(open(server_listdir+"/"+i.split()[1]))))
            print " "*25+self.inblue(i)+" [%s]" % self.inred(quantity)
        print self.indgreen(u"—")*80
        print
    def cat_host(self,groupname):
        data = cPickle.load(open(self.server_list_dir+"/"+groupname,"rb"))
        for i in data.keys():
            print self.inblue(self.decrypt(i))
    def del_host(self):
        while True:
            del_host_list=[]
            n=0
            del_hostname=raw_input("Please enter the host name you want to delete:").strip()
            #del_hostname=self.encrypt(del_hostname)
            while True:
                for i in self.dir_walk(self.server_list_dir):
                    mark_exit=0
                    data=cPickle.load(open(self.server_list_dir+"/"+i.split()[1]))
                    if self.encrypt(del_hostname) in data:
                        #del_hostname=self.decrypt(del_hostname)
                        n+=1
                        del_host_list.append(repr(n)+" "+del_hostname+" "+i.split()[1])
                        print "%s '%s' from group %s" % (self.inred(repr(n)),self.inred(del_hostname),self.inred(i.split()[1]))
                if  del_host_list:
                        hostnumber=len(del_host_list)
                        del_host_number=raw_input("Please enter the number you want to delete a host(1,2...else give up):".strip())
                        for i in del_host_list:
                            #i=self.decrypt(i)

                            hostnumber=hostnumber-1
                            if i.split()[0] == del_host_number:
                                data=cPickle.load(open(self.server_list_dir+"/"+i.split()[2]))
                                del data[self.encrypt(i.split()[1])]
                                cPickle.dump(data,open(self.server_list_dir+"/"+i.split()[2],"wb"))
                                print "Congratulations %s del successfully!" % self.inblue(i.split()[1])
                                if hostnumber !=0:
                                    continue_del=raw_input("按'Y'继续删除,其他返回上层:").strip().lower()
                                    if continue_del.lower() == "y": 
                                        mark_exit=1
                                        del_host_list=[]
                                        n=0                                      
                                        break
                                    else:
                                        
                                        break                    
                else:
                    print "sorry,not found host %s" % self.inred(del_hostname)
                    user_slt=raw_input("按'Y'继续删除，其他返回上层:").strip().lower()
                    if user_slt.lower() == "y":
                        continue
                    else:
                        break
                if mark_exit ==1:
                    continue 
                break 
            break
    def add_group(self):
        """添加分组"""
        self.cat_group(self.server_list_dir)
        while True:
            userselect=raw_input("Enter the group name you want to add:").strip()
            if len(userselect)>=1:
                if os.path.exists(self.server_list_dir+"/"+userselect):
                    print "I'm sorry group '%s' already exists " % self.inred(userselect)
                    continue
                else:
                    data={}
                    cPickle.dump(data,open(self.server_list_dir+"/"+userselect,"wb"))
                    print "Congratulations on your group '%s' added successfully!" % self.inblue(userselect)
                    self.cat_group(self.server_list_dir)
                    user_slt=raw_input("按'Y'继续添加，其他返回上层:").strip().lower()
                    if user_slt == "y":
                        continue
                    else:
                        break
            else:
                print self.inred("sorry,group name not emputy!")
                continue
    def del_group(self): 
        while True:
            mark_exit = 0
            self.cat_group(self.server_list_dir)
            userselect=raw_input("Enter the group name or group number you want to delete:").strip().lower()
            if len(userselect)>=1:
                for  i in self.dir_walk(self.server_list_dir):
                    group_number,group_name=i.split()[0],i.split()[1]
                    if userselect == group_name or userselect==group_number:
                        os.remove(self.server_list_dir+'/'+group_name)
                        print "Congratulations '%s' group del successfully!" % self.inblue(group_name)                       
                        user_slt=raw_input("按'Y'继续删除，其他返回上层:").strip().lower()
                        if user_slt == "y":
                            break  #退出for 继续添加
                        else:
                            mark_exit=1
                            break
                else:
                    print "I'm sorry you select'%s' The group name or group number does not exists!" % self.inred(userselect)
                    continue
                if mark_exit==1:
                    break  #退出while循环返回上层
            else:
                print self.inred("sorry,group name not emputy!")
    def rename_group(self):
        while True:
            mark_exit= 0
            self.cat_group(self.server_list_dir)
            userselect=raw_input("Enter the group name or group number you want to rename:").strip().lower()
            if len(userselect)>=1:
                for  i in self.dir_walk(self.server_list_dir):
                    group_number,group_name=i.split()[0],i.split()[1]
                    #判断要修改的组名是否存在
                    if userselect == group_name or userselect==group_number:
                        while True:
                            new_groupname=raw_input("Please enter the new group name:").strip()
                            #判断输入是否为空
                            if len(new_groupname)>=1:
                                #判断组名是否存在
                                if os.path.exists(self.server_list_dir+"/"+new_groupname):
                                    print "I'm sorry group '%s' already exists " % self.inred(new_groupname)
                                    continue
                                else:
                                    os.rename(self.server_list_dir+"/"+group_name,self.server_list_dir+"/"+new_groupname)
                                    print "Congratulations '%s' group modify successfully,new group name is '%s'!" % (self.inblue(group_name), self.inblue(new_groupname))                     
                                    user_slt=raw_input("按'Y'继续修改，其他返回上层:").strip().lower()
                                    if user_slt == "y":
                                        break  #退出内层while
                                    else:
                                        mark_exit=1
                                        break
                            else:
                                print self.inred("sorry,group name not emputy!")
                        break #退出for循环返回到外层while 
                else:
                    print "I'm sorry you select'%s' The group name or group number does not exists!" % self.inred(userselect)
                    continue
            else:
                print self.inred("sorry,group name not emputy!")
            if mark_exit == 1:
                break   #退出while 返回上层目录
    def addhostto_group(self):
        while True:
            print "Welcome to the Add Host function:"
            self.printindex("1 One by adding a host","2 Bulk add host","3 Back to higher")
            userselect=raw_input('Please select the services you need number(1,2or 3):').strip()
            if userselect=="1":
                while True:
                    while True:
                        hostname=raw_input("please input your hostname or ip:").strip()
                        if len(hostname)<1:
                            print self.inred("sorry, hostname is not emputy!")
                            continue
                        elif len(hostname)<=3:
                            print "sorry,your hostname '%s' is too short" % self.inred(hostname)
                            continue
                        break
                    while True:
                        try:
                            port=int(raw_input("please input your ssh services port:").strip())
                            break
                        except ValueError,e:
                            print self.inred("You must enter a valid port!")
                            continue
                    while True: 
                        username=raw_input("please input your username:").strip()
                        if len(username)<1:
                            print self.inred("sorry, username is not emputy!")
                            continue
                        break
                    while True:
                        passwd=raw_input("please input your passwd:")
                        if len(passwd)<1:
                            print self.inred("sorry, username is not emputy!")
                            continue
                        passwd=self.encrypt(passwd)
                        hostname=self.encrypt(hostname)
                        port=self.encrypt(repr(port))
                        username=self.encrypt(username)
                        break
                    self.ssh2_conn(ip=hostname,port=port,username=username,passwd=passwd)
                    self.ok_count={}
                    self.error_count={}
                    def addhost():
                        while True:
                            mark_exit,mark_group_exit=0,0
                            select_group=raw_input("Enter the group name or group number you want host to group:").strip().lower()
                            if len(select_group)>=1:
                                for  i in self.dir_walk(self.server_list_dir):
                                    group_number,group_name=i.split()[0],i.split()[1]
                                    if select_group == group_name or select_group==group_number:
                                        data = cPickle.load(open(self.server_list_dir+"/"+group_name,"rb"))
                                        if hostname in data:
                                            print "Sorry,host '%s' has been in the group '%s' exist!" % (self.inred(hostname),self.inred(group_name))
                                            mark_group_exit=1
                                            break
                        #                passwd=self.encrypt(passwd)
                                        data[hostname]=[port,username,passwd]
                                        cPickle.dump(data,open(self.server_list_dir+"/"+group_name,"wb"))
                                        print "Congratulations,'%s' add to group '%s' successfully!" % (self.inblue(self.decrypt(hostname)),self.inblue(group_name))
                                        self.cat_group(self.server_list_dir)
                                        user_slt=raw_input("按'Y'继续添加，其他返回上层:").strip().lower()
                                        if user_slt == "y":
                                            break  #退出for循环
                                        else:
                                            mark_exit=1
                                            break                                                   
                                else:
                                    print "I'm sorry you select'%s' The group name or group number does not exists!" % self.inred(select_group)
                                    continue
                                if mark_group_exit == 1:
                                    continue
                            else:
                                 print self.inred("sorry,group name not emputy!")
                                 continue
                            break
                        return mark_exit
                    if len(self.ok_count) != 0:
                        self.cat_group(self.server_list_dir)                    
                        return_value=addhost()
                        print return_value
                        if return_value == 1:
                            break    
                    else:
                        addgroup_select=raw_input(self.inred("Warnning,connection failed,Continue to add('Y' add,else give up):"))
                        if addgroup_select.strip().lower() =="y":
                            self.cat_group(self.server_list_dir)
                            return_value=addhost()
                            print return_value
                            if return_value == 1:
                                break 
                        else:
                            break  
            elif userselect == "2":
                print """
                        欢迎使用批量添加主机:
                        1、你可以一次添加多个主机到组
                        2、文件中每行必须以这种格式存储 hostname,port,username,passwd
                      """
                while True:
                    file_dict={}
                    line=0
                    hostfile_path=raw_input("Please enter the path to the file storage host information,example (/tmp/hostinfo.txt):").strip()
                    try:
                        with open (hostfile_path,'rb') as f:
                            for i in f:
                                line+=1
                                s=i.strip('\n').split(",")
                                ip,port,username,passwd=self.encrypt(s[0]),self.encrypt(s[1]),self.encrypt(s[2]),self.encrypt(s[3])
                                file_dict[ip]=[port,username,passwd]
                        self.multi_threading(file_dict,self.ssh2_conn)
                        conn_error=len(self.error_count)
                        conn_ok=len(self.ok_count)
                        self.error_count={}
                        self.ok_count={}
                        #print conn_ok
                        def Bulk_host(fileUP_dict):
                            while True:
                                self.cat_group(self.server_list_dir)   
                                select_group=raw_input("Enter the group name or group number you want host to group:").strip().lower()
                                if len(select_group)>=1:
                                    for i in self.dir_walk(self.server_list_dir):
                                        group_number,group_name=i.split()[0],i.split()[1]
                                        if select_group == group_name or select_group==group_number:
                                            data = cPickle.load(open(self.server_list_dir+"/"+group_name,"rb"))
                                            data.update(fileUP_dict)
                                            cPickle.dump(data,open(self.server_list_dir+"/"+group_name,"wb"))
                                            break
                                    else:
                                        print "I'm sorry you select'%s' The group name or group number does not exists!" % self.inred(select_group)
                                        continue
                                else:
                                    print self.inred("sorry,group name not emputy!")
                                    continue
                                break 
                        if conn_error>0:
                            add_select=raw_input("%s hosts connection fails, if the connection failed also added to the group('Y' add,else give up fails host):" % self.inred(str(conn_error))) 
                            if add_select.strip().lower() =="y":
                                Bulk_host(file_dict)
                                print self.inblue("Congratulations,add host to group successfully!")
                            else:
                                if conn_ok>0:
                                    Bulk_host(self.ok_count)
                                    print self.inblue("Congratulations,conns ok host add to group successfully!")
                                else:
                                    pass
                        else:
                            Bulk_host(file_dict)
                            print self.inblue("Congratulations,add host to group successfully!")
                        break 
                    except IOError,e:
                        e=str(e)
                        print self.inred(e)
                    except IndexError,e:
                        e=str(e)
                        print "sorry,format error", self.inred("on lines "+repr(line))
                    except ValueError,e:
                        print "sorry,Port number must be an integer!",self.inred("on lines "+repr(line))
            elif userselect == "3":
                break
            else:
                pass
class BufferAwareCompleter(df_class.Universal):
    def __init__(self,allcmd):
       # self.options = custcmd  #自定义的命令
        self.current_candidates = [] 
        self.allcmd = allcmd
        return 
    def complete(self, text, state):
        response = None
        if state == 0:    
            origline = readline.get_line_buffer() #返回行缓冲区的当前内容
            begin = readline.get_begidx() #返回行自动补全的范围的开始
            end = readline.get_endidx() #返回行自动补全的范围的结束
            being_completed = origline[begin:end]  #返回行数据
            words = origline.split() #因为有2级命令  分割出那级命令
 
            if not words: #如果使用tab是空 ，返回所有一级命令
                self.current_candidates = sorted(self.allcmd) 
            else:
                try:
                    if begin == 0: #如果是第一个命令
                        candidates = self.allcmd
                    else:
                        if origline.endswith(' '):words.append('')  #如果使用tab时以空格结尾，则在words列表追加一个元素，以便于后边判断要输入几个参数
                        basedir,basefile = os.path.split(words[-1]) 
                        if words[0] == 'get' and len(words) == 3:   #如果get 命令的第二个参数，返回本机的路径
                            candidates = self.alllocalpath(basedir)
                        elif words[0] == 'put' and len(words) == 2: #如果put　命令的第一个参数，返回本机的路径
                            candidates = self.alllocalpath(basedir)
                        else:
                            candidates = self.alllocalpath(basedir)   #默认返回远程机器上的路径
                        being_completed = basefile
                     
                    if being_completed: #如果有字母
                        self.current_candidates = [ w for w in candidates
                                                    if w.startswith(being_completed) ]  #对比是不是注册的命令是不是以这个或这些字母开头
                    else:
                        self.current_candidates = candidates  #返回所有
 
                except (KeyError, IndexError), err:
                    self.current_candidates = []
 
        try:
            response = self.current_candidates[state]
        except IndexError:
            response = None
        return response
#logging.basicConfig()
readline.set_completer_delims(' \t\n`~!@#$%^&*()=+[{]}\\|;:\'",<>/?') #去掉-分隔符
a=Operatinghost()
readline.set_completer(BufferAwareCompleter(a.alllocalcommands()).complete)
readline.parse_and_bind('tab: complete')
#s=raw_input("hello:")
a.user_login()
