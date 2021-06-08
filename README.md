# 2019 Defcon DFIR CTF Write-up "Memory forensics"

Hello forks,

I'm solving memory  forensics challenge with `volatility 2` framework from **Defcon DFIR CTF 2019** [here](https://defcon2019.ctfd.io/challenges)

You can download the snapshot from [here](https://drive.google.com/drive/folders/1JwK8duNnrh12fo9J_02oQCz8HlILKAdW)

Lets G00000 ...

**********************************************



### 01. get your volatility on - 5 Points

“What is the SHA1 hash of triage.mem?”

Solve:-

we just using tool `sha1sum` to get the hash.

### **`sha1sum Triage.mem`**

### **`flag<C95E8CC8C946F95A109EA8E47A6800DE10A27ABD>`**


*************
*************


### 02. pr0file - 10 Points

"What profile is the most appropriate for this machine? (ex: Win10x86_14393)"

Solve:-

We using a plug-in `imageinfo` and choose the first suggestion :

### `python2 /opt/volatility/vol.py -f Triage.mem imageinfo`

#### ![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-07%2018-08-53.png)

## `flag<Win7SP1x64>`

This is essential step in the discovery process and we will use the `profile` 4ever with volatility 2.


*************
*************


### 03. hey, write this down - 12 Points

“What was the process ID of notepad.exe?”

Solve:-

We use plug-in `pslist`  it list all processes run in the memory :

### `python2 /opt/volatility/vol.py -f Triage.mem pslist`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-07%2018-27-51.png)

### `flag<3032>`


*************
*************



### 04. wscript can haz children - 14 Points

“Name the child processes of wscript.exe.”


Solve:-

Just use `pstree` plug-in and you will see the parents and children but I will `grep` the processes to save effort and I used `A1` to see 1 line under wscript process : 

### `python2 /opt/volatility/vol.py -f Triage.mem pstree |grep -A1 wscript.exe`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-07%2018-38-16.png)

### `flag<UWkpjFjDzM.exe>`

it seems like a **malicious** **process**  Hmmmmmmmmmmmmmmmmmmmmmm .. Let's continue 


*************
*************



### 05. tcpip settings - 18 Points

“What was the IP address of the machine at the time the RAM dump was created?”


Solve:-

`netscan` plug-in is used to discover IPs and protocols in the memory and look under 'Local Address' column :

### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 netscan`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-07%2018-48-48.png)

### **`flag<10.0.0.101> `**

*************
*************


### 06. intel - 18 Points

“Based on the answer regarding to the infected PID, can you determine what the IP of the attacker was?”


Solve:-

We still in `netscan` solution.. Just scroll down  and look to **Foreign Address** column :

### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 netscan`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-07%2018-56-24.png)

### `flag<10.0.0.106>`


*************
*************



### 07. i <3 windows dependencies - 20 Points

“What process name is VCRUNTIME140.dll associated with?”


Solve:-

Look to name, this is a dll file so we use `dlllist` plug-in and explore it's results at the first then..

use `grep` to specify the flag

##### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 dlllist | grep VCRUNTIME140.dll -B 30`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2014-49-33.png)

### `flag<OfficeClickToR>`

We used  ***-B 30*** to get previous 30 line before the dll file.


*************
*************




### 08. mal-ware-are-you - 20 Points

“What is the md5 hash value the potential malware on the system?”


Solve:-

First, We will dump the executable file for malicious process

second, We will calculate the hash

##### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 procdump -p 3496 --dump-dir=./`

#### `md5sum executable.3496.exe`

  ![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2014-56-41.png)

### `flag<690ea20bc3bdfb328e23005d9a80c290>`


*************
*************



### 09. lm-get bobs hash - 24 Points

“What is the LM hash of bobs account?”

Solve:-

use `hashdump` and check bob :

result =  name : :id: : account hash : pass hash

### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 hashdump`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2015-05-16.png)

### `flag<aad3b435b51404eeaad3b435b51404ee>`



*************
*************


### 10. vad the impaler - 25 Points

“What protections does the VAD node at 0xfffffa800577ba10 have?”

Solve:-

just explore with `vadinfo` then use grep :

##### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 vadinfo | grep "0xfffffa800577ba10" -A3`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2015-10-55.png)

### `flag<PAGE_READONLY>`


*************
*************



### 11. more vads?! - 25 Points

“What protections did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have?"

Solve:-

from previous plug-in we can understand the results so we can grep with the right text :

`python2 /opt/volatility/vol.py -f Triage.mem--profile=Win7SP1x64 vadinfo | grep "Start 0x00000000033c0000 End 0x00000000033dffff" -A3`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2015-17-46.png)

#### `flag<PAGE_NOACCESS>`


*************
*************



### 12. vacation bible school - 25 Points

“There was a VBS script run on the machine. What is the name of the script? (submit without file extension)”

Solve:-

With `cmdline`  plug-in we will get the result directly :dancer:

#### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 cmdline |grep ".vbs"`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2015-20-35.png)

### `flag<vhjReUDEuumrX>`


*************
*************



### 13. thx microsoft - 25 Points

“An application was run at 2019-03-07 23:06:58 UTC, what is the name of the program? (Include extension)”

Solve:-

`shimache` plug-in gets it directly with grep

##### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 shimcache | grep "2019-03-07"`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2015-27-03.png)

### `flag<Skype.exe>`


*************
*************



### 14. lightbulb moment - 35 Points

“What was written in notepad.exe in the time of the memory dump?”

Solve:-

First, we will dump the memory space with contain the notepad content then.. We will search in the dumped file

After trying The flag is encoded :)  so we used `-e l`

##### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 memdump -p 3032 --dump-dir=./`

#### `strings -e l 3032.dmp | grep "flag"`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2015-37-00.png)

#### `flag<REDBULL_IS_LIFE>`

REDBULL_IS_LIFE ??? I hate this shit.. what everrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr :(



*************
*************


### 15. 8675309 - 35 Points

“What is the shortname of the file at file record 59045?”

Solve:-

record? Hmmmmmmmmmmmm... Did you heard about **Master file table**? never mind

It's `mftparser` plug-in time

##### `python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 mftparser | grep "59045" -A 20`

![](https://github.com/elnoty/memory-forensics-writeup/blob/main/Images/Screenshot%20from%202021-06-08%2016-01-44.png)

#### `flag<EMPLOY~1.XLS>`


*************
*************



### 16. whats-a-metasploit? - 50 Points

“This box was exploited and is running meterpreter. What PID was infected?”


Solve:-

From previous questions we already know the infected process but we can dump the executable file with `procdump` and check its hash on  [VirusTotal Report](https://www.virustotal.com/gui/file/b6bdfee2e621949deddfc654dacd7bb8fce78836327395249e1f9b7b5ebfcfb1/detection)

### `flag<3496>`

*************
*************
Thank you for reading ^_^ 


