# ESET CRACK ME - Stage 1

For recruiting new talent, ESET published a public crack me. This gives you the opportunity to join their team to face global cyber-threats. According to the website the crackme.exe contains **3 hidden passwords** and contains hidden files, texts, conditional tasks, protection against debuggers and other pitfalls. They also encourage you to send your report even if you are unable to pass all the challenges. ESET is interested in your thought process in reverse engineering.    

[Crackme]: https://join.eset.com/en/challenges/crack-me

## Download the crackme.exe program

ESET offers you the crackme.exe through a download button. When clicking on the link it is sending you "crackme.zip". So someone's first reaction is to unpack it with tools like 7zip or Winrar. If you actually unpack the executable it will extract the executable headers like .data, .rdata, .text and certificate. If this happens this actually looks confusing, but checking the zip with a hex editor, you notice quickly that it starts with a MZ header. This means that the zip isn't a zip but an executable. **First challenge is to change .zip to .exe**. 

## Behavior

Understanding in which language the challenge is written you can check with a tool called DIE (Detect It Easy). Die has a ton of signatures to identify the compiler and linker information. Do keep in mind that DIE isn't fool proof and you're depending on the community writing these signatures. In this case the challenge is written in C/C++ and compiled with Microsoft Visual 2012 with update 3. The reason I like to know is to understand how the compiler has optimized the code. A good resource is https://godbolt.org/ where you can test your code against multiple compilers and versions.  

It is not always recommended to run your executable without knowing what it exactly does, but in this case let's make an exception. Just to be safe I've created a snapshot of my virtual machine and made sure the internet is cut off. Running the executable it's asking for a valid password. Depending on the results given, it returns "**Wrong password!**". Now we can assume we're looking for something like scanf, fscanf, getline, stdin, **ReadConsoleA**, etc.

## String analyzing

For static analysis we've a few tools in our arsenal. The options are IDA, Ghidra, Binary Ninja, Hopper, etc. But for this exercise I will use a mix of various tools to analyze the binary. These Free tools are IDA FreeWare and Ghidra for it's pseudo C. Open crackme.exe in IDA and let's search for our first obtained string **"Wrong Password!"**. In IDA pressing, shift + F12 or via the menu View -> Open subviews -> Strings, you can see all the strings it has found within the executable. It gives us also an idea what is contained in the executable by just looking at the strings. Searching for our string "Wrong password!" returns no results, this means it is properly **obfuscated**. This is a technique malware authors use to hide strings. Hoping researchers will miss it and mark it as safe. Another reason why you want to look at strings is that malware authors use to compile their executables statically. This means that strings of other modules are within the executable. This also gives you an indication of what the executable does.

## Finding _main

As soon as you've loaded the challenge, crackme.exe, into IDA or disassembler of choice it will take you to the CRC start routine. This isn't the entry point of the application. To find main we can look for three pushes before a call. Why three pushes? With C/C++ the main has three arguments. Even when you use void main or do not declare, the compiler still compiles it with the arguments.

```c
int main( int argc,      // Number of strings in array argv
          char *argv[],   // Array of command-line argument strings
          char *envp[] )  // Array of environment variable strings
```

[Main function]: https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170

We also know that the value of main is returning zero to the operating system. You don't need to have a hardcoded `return 0;` in your code. The compiler does that for you. The return value is always in the eax register so we have to find the last function that has set eax to zero. Hence we have to work backwards in the CRC start routine to find main. In our example main starts at `sub_4013F0` and can change the function to `_main` for IDA to make it a cdecl function. 

### Anti-Debug

###### IsDebuggerPresent

As soon as we identified the main IDA recognized that the first call was "IsDebuggerPresent" at offset004013F6. If the flag is set it will exit the program. An option is to patch the executable from jump zero to jump not zero at offset 004013FE.

```c
//C/C++ representation of IsDebuggerPresent()

if (IsDebuggerPresent())
    ExitProcess(-1);
```

[IsDebuggerPresent]: https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent

###### GetTickCount

Glancing over main,  `GetTickCount` is used right after `ReadConsoleA`. This is another anti-debugging trick. Keep in mind that when a process is traced in a debugger, there is a delay between instruction and execution. In this case the `GetTickCount` starts at offset `00401475` and stops at offset `0040163A`. The results are subtracted and compared. If the result is higher than 100 milliseconds, the program exits.

```assembly
; Example in IDA

mov     [ebp+var_10], eax
mov     eax, [ebp+var_10]
sub     eax, [ebp+var_14]
cmp     eax, 100
```

```c
// C/C++ representation of GetTickCount()

bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = GetTickCount();
    // printf("Hello, World!");
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}
```

[GetTickCount]: https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount

###### BeingDebugged

The `mov eax, large fs:30h` is loading the address of the Process Environment Block (PEB) which can access the FS segment. To indicate if a process is currently being debugged. 

```assembly
; Example in IDA
.text:00401622                 mov     eax, large fs:30h
```

```c
// C/C++ representation of BeingDebugged
PPEB pPeb = (PPEB)__readfsdword(0x30);
```

[PEB structure]: https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb



## Obfuscated strings

What we know is that we're looking for a string "Please enter valid Password". So we're looking for a function that outputs strings on a screen. At offset `0040143F` there is a call to `WriteConsoleA`, which writes a character string to a console screen. Best way is to work ourselves up to find a function that is deobfuscating strings. Doing so, at offset `0040141A`  in _main `sub_4013A0` is a function with 4 arguments. One of the offset `00401415` looks like something like an obfuscated string.

```assembly
; Example in IDA
.text:0040140F                 push    3
.text:00401411                 push    25h ; '%'
.text:00401413                 push    1Fh
.text:00401415                 push    offset Buffer   ; "uDNOBQ"
.text:0040141A                 call    sub_4013A0
```

Going into sub_4013A0 you notice quickly in IDA graph that it is looping. Var_4 is the counter and gets its variable from the function.Which in this case is 1Fh (h stands for hex) so 31 loops. Which means we've a string of 31 characters, The string `Please enter valid Password : \n` has a length of 31. This means we're on the right track. Going over the code with Ghidra for the C opcode. We see that it loops 31 times, the offset Buffer is being looped per character, the key first starts with 25h, adds 3 every time to the key (Eg. 25h, 28h 2Bh, 2Eh, 31, 34, etc.) and xor the offset Buffer with the new key. 

In _main the function to deobfuscate is called 3 times throughout the code.

```Please enter valid password : Wrong password!
Please enter valid password : 

Wrong password!

!Good work. Little help:
char[8] = 85
char[0] + char[2] = 128
char[4] - char[7] = -50
char[6] + char[9] = 219
```

The code for automating:

```nim
# strings_xor.nim

import std/[streams]

const buffer = {
  # File offset: Buffer
    0x16000: [              # file offset: Please enter valid Password :             
      0x1f,                 # unsigned_int_a2: Size of string
      0x25,                 # int_a3: key
      3                     # int_a4: sum 
    ],
    0x16020: [              # file offset: Wrong Password!
      0x11,                 # unsigned_int_a2: Size of string
      0x16,                 # int_a3: key
      7                     # int_a4: sum 
    ], 
    0x16038: [              # file offset: !Good work. Little Help: char[8] = 85; char[0] +
      0x6e,                 # unsigned_int_a2: Size of string
      0x12,                 # int_a3: key
      5                     # int_a4: sum
    ],   
  }

var strm = newFileStream("crackme.exe", fmRead)

proc sub_4013A0(buffer: openArray[byte], unsigned_a2, a3, a4: int): string =
  var 
    a3: int = a3
    x: int

  for var_4 in 0..<unsigned_a2:

    if a3 <= 255:
      x = int(buffer[var_4]) xor a3
   	
   	a3 += a4

    stdout.write(chr(x))
    
for i in 0..<buffer.len:
  var buff: array[120, byte]   # With nim you've to evaluate at compile time.
  strm.setPosition buffer[i][0]
  discard strm.readData(buff[0].unsafeAddr, buffer[i][1][0])
  discard sub_4013A0(buff, buffer[i][1][0], buffer[i][1][1], buffer[i][1][2])
```

At offset `004014A5` between the `GetTickCount` and `BeingDebugged` there are a bunch of calculations going before the password is checked at function `sub_401300`. At first this doesn't make any sense, but with the tip we got from deobfuscating strings. This looks like it comes straight from Facebook. Think about the  "99% of the people who can't solve", "Solve this if you are a genius!", "95% of people answer it wrong" advertisements on Facebook.

```assembly
; Example in IDA
mov     edx, 1
imul    edx, 7
movsx   eax, byte ptr [ebp+edx-32]
mov     ecx, 1
imul    ecx, 6
movsx   edx, byte ptr [ebp+ecx-20h]
add     eax, edx
cmp     eax, 0CDh
```

If we look at the first comparison of `char[7] == ecx 7` and `char[6] == ecx 6` it holds a total of `205 == 0CDh`. If we do that for all we get the following list.

```
char[7] + char[6] = 205
char[8] + char[5] = 201
char[7] + char[6] + char[3] = 314
char[9] + char[4] + char[8] + char[5] = 367
char[1] + char[0] = 194
char[0] + char[1] + char[2] + char[3] + char[4] + char[5] + char[6] + char[7] + char[8] + char[9] = 923
```

To find some of the remaining characters we can do some calculations, like for example to get `char3` `char[7] + char[6] + char[3]` - `char[7] + char[6]` is the same as 314 - 205 = 109. With the hint, we got from deobfuscating a few more letters.

```
char[0] = 80		-> P
char[1] = 114		-> r
char[2] = 48		-> 0
char[3] = 109		-> m
char[4]
char[5] = 116		-> t
char[6]
char[7]
char[8] = 85		-> U
char[9]
```

Looking back at `sub_401300` has to password has to match 0x1928F914

```
; Example in IDA
.text:00401658                 lea     ecx, [ebp+Buffer]
.text:0040165B                 push    ecx
.text:0040165C                 call    sub_401300
.text:00401661                 cmp     eax, 1928F914h
```

Having all the details on how the password is calculated. We can get the remaining characters by brute forcing the password and checking it against `0x1928F914`  to verify if the password is correct. Also known as crc (Cyclic Redundancy Check) 

```nim
# Bruteforce.nim

import std/[bitops]

proc crc(password: openArray[uint32]): uint32 = 
  var rst: uint32

  for i in 0..<password.len:
    rst = rotateRightBits(rst, 9) xor password[i].uint32 # See offset 00401331 in crackme.exe
  return rst

var 
  pwd: array[10, uint32]                            # Array with len of 10 uint32
  max = rotateRightBits(126.uint32, 1)              # 126 = Decimal - ascii = ~
                                                    # Which is 63 characters loaded
pwd[0] = 80                                         # P
pwd[1] = 114                                        # r
pwd[2] = 48                                         # 0
pwd[3] = 109                                        # m
pwd[5] = 116                                        # t
pwd[8] = 85                                         # U

for i in 0..max:
  pwd[4] = i.uint32

  for j in 0..219:                                # ch[6] + ch[9] = 219                               
    pwd[9] = j.uint32                             # Just loop everything

    pwd[6] = 219 - pwd[9]                         # subtract to find pwd[6]
    pwd[7] = 205 - pwd[6]                         # subtract to find pwd[7]

    if(crc(pwd) == 0x1928F914):                   # CRC check see offset 00401661 in crackme.exe
      for i in 0..<pwd.len():                     # If found print pwd
        stdout.write(char(pwd[i]))
      echo()
      quit(0)
```

To check if the password works we get a new message saying that we have the right password, only there is some unreferenced data that we need to decrypt in the same way. That means we are looking for a blob of data that is unreferenced in the .data header.

```
Please enter valid password : Pr0m3theUs
Congratulations! You guessed the right password, but the message you see is wrong.
Try to look for some unreferenced data, that can be decrypted the same way as this text.
```

Going through _main there is another function at offset `0040167E` that is trying to deobfuscate a string. The results are coming from lpBuffer. If you follow lpBuffer it moves to `.data:00418034 lpBuffer  dd offset unk_4180A8` and you get `unk_4180A8` which is at file offset `160A8`.

```
; Example in IDA
.text:00401668                 push    2
.text:0040166A                 mov     edx, [ebp+NumberOfCharsRead]
.text:0040166D                 push    edx
.text:0040166E                 lea     eax, [ebp+Buffer]
.text:00401671                 push    eax
.text:00401672                 push    100h
.text:00401677                 mov     ecx, lpBuffer
.text:0040167D                 push    ecx
.text:0040167E                 call    sub_401350
```

The important information being pushed to `sub_401250` is `2`,  `Pr0m3theUs` and `0x100`. These are the key ingredients to deobfuscate the last string we're looking for. What it does is jumping to file offset 160A8 + 0x100. The new address is 161A8,  this will be decoded with the password `Pr0m3theUs` and some xor.

```nim
# strings_xor_2.nim
import std/[streams]

const 
  key = "Pr0m3theUs"                                                    # Key from brute forcing
  address = {
  # File offset: Buffer
    0x160A8: 66,                                                        # File offset 160AB from unk_4180A8 via lpBuffer
  }																		# Buffer is size of string

proc sub_401350(a: openArray[byte], buffLen:int): string =

  for i in 0..<buffLen:                                                 # Char xor 2. From offset 00401668 push    2
   stdout.write(chr(a[i] xor 2 + byte(key[i mod key.len])))             # Key mod key length
  echo()                                                                # Char xor 2 + key mod key length

var strm = newFileStream("Notfree.exe", fmRead)

for i in 0..<address.len:
  var buff: array[100, byte]   # With nim you've to evaluate at compile time.
  strm.setPosition address[i][0] + 0x100                                # Goto address 0x160A8 + 0x100 = 161A8
  discard strm.readData(buff[0].unsafeAddr, address[i][1])              # 0x100 comes from offset 00401672 being pushed to the function
  discard deobfuscation(buff, address[i][1])
```

Once the string is deobfuscated, it will give a link to the Eset website for stage 2 to be cracked. This means we're done with this first crackme. I don't see anything of interest to keep on investigating. It was an interesting exercise teached me a bit more about programming with nim. 

As last, a few books I like to share I think is worth reading:

[Nim in Action]: https://www.amazon.com/Nim-Action-Dominik-Picheta/dp/1617293431
[Malware Analysis and Detection Engineering]: https://www.amazon.com/Malware-Analysis-Detection-Engineering-Comprehensive/dp/1484261925/
