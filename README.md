# Bsides Delhi 2020 Writeup - My Part

Welcome to my write-up! Today we are taking a look at Bsides Delhi 2020, which challenges are really awesome and interesting. Some of the challenges were out of my league (at least for now), and some of them I managed to finish as a team. I'm more than happy to finish two of the Forensics challenges  which I really enjoy doing in the team. We finished first! That's why I want to make this write-up; to share the knowledge and the great world of forensics.

## 1st Challenge: Heisenberg's Password
So this is a memory forensics challenge, which I solve quite often with Volatility, a memory forensics tool from Volatility Foundation. We got this humongous raw file, which I always reckon as a memory dump. 

> Description: Some undercover cops were trying to get info from a drug dealer named Heisenberg. He stored all the details of the drug mafia in an encrypted file in his PC. PC is with cops now. But they don't know the password. According to the Intelligence team, Heisenberg has weak memory and He used to store his strong password as different parts in different places in his wife's PC. The Intelligence team were able to collect his wife's PC memory dump. The Intelligence team informed us that getting the answers for given questions and setting them in a given format might give us the password. So could you help them to get the password?
>PS: Follow the order of questions while wrapping the answers
> When is the last time loveyou.png modified? eg: 2020–10–10_11:45:33
> What is the physical offset of Loveletter text? eg: 0x000000007ac06539
> When is the last time the MEGA link opened? eg: 2020–10–10_11:45:33
> Wrap the answers in the format: BSDCTF{2020–10–10_11:45:33$7ac06539$2020–10–10_11:45:33}

Oh, I love this. This is like SANS forensics challenge, which is not necessarily a flag finding, but also learning what you could find in a memory dump.

### 1st section - Identifying what dump is this
Is it brown? Yellow? Or Windows 98? Usually it will be obviously on Windows due to its unique Little-Endian style of encoding. BUT to check it, we just need to do the Volatility magic command.

`python vol.py -f ../../BsidesDelhi/Win7mem/Win7mem.raw imageinfo`

`imageinfo` will tell you based on KDBG search, which is a Windows-thing for debugging purposes. From the [Security StackExchange Answer](https://security.stackexchange.com/a/71117) :

_The KDBG is a structure maintained by the Windows kernel for debugging purposes. It contains a list of the running processes and loaded kernel modules. It also contains some version information that allows you to determine if a memory dump came from a Windows XP system versus Windows 7, what Service Pack was installed, and the memory model (32-bit vs 64-bit)._

So yeah, just to see the Windows version of this, you need to parse the debugging style.
```
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/this/should/be/my/directory/Win7mem.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800029fc070L
          Number of Processors : 2
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff800029fdd00L
                KPCR for CPU 1 : 0xfffff880009ee000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-09-30 14:08:36 UTC+0000
     Image local date and time : 2020-09-30 19:38:36 +0530
```
Cool, so we get the Windows version which is `Win7SP1x64` or Windows 7 Service Pack 1 64-bit. Now what?

### 2nd section - Finding the last modified file date on the dump
Hmmm... how do we find the date of modified file? Using Volatility, simply put a `mftparser` command. This should parse the MFT of the dump. What's MFT, you might ask? According to [The official Windows Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table):

_The NTFS file system contains a file called the master file table, or MFT. There is at least one entry in the MFT for every file on an NTFS file system volume, including the MFT itself. All information about a file, including its size, time and date stamps, permissions, and data content, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries._

Cool, so metadata of a file is stored in MFT which we can acquire by using Volatility. So we can run command:

`python vol.py -f ../../BsidesDelhi/Win7mem/Win7mem.raw --profile=Win7SP1x64 mftparser > ../../BsidesDelhi/Win7mem/mft.txt`.

It will be a long output so I need to put it in a TXT file to make sure I didn't need to run the same command again.

So we left with `mft.txt` with 300,000 lines of output. But we just need to find the interesting file of `loveyou.png`. Using simple search, we could find two entries of `loveyou.png`:

```
Line 44562: 2020-09-30 13:54:56 UTC+0000 2020-09-30 13:54:56 UTC+0000   2020-09-30 13:54:56 UTC+0000   2020-09-30 13:54:56 UTC+0000   Users\bsides\Desktop\loveyou.png

Line 106429: 2020-09-30 13:34:58 UTC+0000 2020-09-30 13:34:58 UTC+0000   2020-09-30 13:34:58 UTC+0000   2020-09-30 13:34:58 UTC+0000   Users\bsides\DOWNLO~1\loveyou.png
```

The second date of a line is the modified date, so we get `2020-09-30 13:54:56` as the first answer.

### 3rd section - Finding the actual offset of a file

So in Volatility we can simply use `filescan` to get the file listing and its offset, because of NTFS nature of tracking things.

`python vol.py -f ../../BsidesDelhi/Win7mem/Win7mem.raw --profile=Win7SP1x64 filescan > ../../BsidesDelhi/Win7mem/filelist.txt`

Again, we're putting it in TXT because there is an enormous amount of file here. After it's finished, we can look around and search the interesting file.

`Line 2983: 0x000000007fa07960     16      0 RW-r-- \Device\HarddiskVolume2\Users\bsides\Desktop\loveletter.txt`

Got it. The second answer is `7fa07960`.

### 4th section - Finding the browser history :floshed:

Are you using your Windows to open questionable websites? Worry yes, with the memory dump we can get your recent history. First we have to look for the browser it is using by looking at the processes using `cmdline` command. But apparently there is no info about the browser, at least not running. So, blindly, I'm using `chromehistory` plugin by [superponible](https://blog.superponible.com/2014/08/31/volatility-plugin-chrome-history/). And apparently it works, and returned several recent history of the browser.
```
...
    33 https://www.google.com/                                                          Google                                                                                2     1 2020-09-30 14:05:05.765148        N/A       
    32 https://mega.nz/file/iehAyJYR#VdDc7oPuH225hp_orw4TswOU5dOSLMhqntpfoVEGjds        https://mega.nz/file/iehAyJYR#VdDc7oPuH225hp_orw4TswOU5dOSLMhqntpfoVEGjds             2     1 2020-09-30 14:04:39.493154        N/A      
...
```

This is the most recent Mega link opened. So the third answer is `2020-09-30 14:04:39`

So, based on those answers, the flag is:

`BSDCTF{2020-09-30_13:54:56$7fa07960$2020-09-30_14:04:39}`

##2nd Challenge - Upside Down

_Description: My weird minded friend has a habit of sending messages through memes. He never used to say anything straight forward. Can u find what he is trying to say?_

And we got an `.MSG` file. Of course, first thing I tried, because it's an MSG file, is to ~~put it in food~~ open it in Microsoft Outlook. But it won't open. And then I searched about the file signature of MSG file, it doesn't match with our MSG file. Huh, so I wondered around. Reading the challenge name, I could try to read the reversed byte, cuz it's _upside down_. "Haha," I thought to myself, thinking that it might be a ridiculous method. 

```
00 00 00 00 FF ED 00 00 00 D5 00 10 00 10 00 00 ����ÿí���Õ����
...
```

What kind of file has four null bytes as header??? I searched and there are some but there are far too niche for plain user to use it. So then my gut tells me that I should really try to use _that_ method.

```
...
FE 20 D2 15 74 0B DB 00 80 00 10 00 41 40 30 B4 
05
```
Reverse the last byte: `50 4B 03 04`.... I noticed something really familiar. It turns out it's a PKZIP archive file signature! My gut was working! So I made a simple script to reverse the hex byte and rewrite it to a new file.

```
import binascii
filename = 'm3ss4g3.msg'
with open(filename, 'rb') as f:
    content = f.read()
hexfile = binascii.hexlify(content).decode()
hexfilerev = hexfile[::-1]
binfilerev = bytes.fromhex(hexfilerev)
with open('m3ss4g3.zip', 'wb') as f:
	f.write(binfilerev)
```

Now I can open it as zip. But the zip is password protected, so threw it to my friend to crack it only to see the password is `rainbow`. There is an PNG image inside of a Barack Obama's Stale Meme, _Not Bad_, with the flag.

`BSDCTF{n0t_b4d_u_g0t_my_m3ss4g3}`

I hope you like the writeup!
