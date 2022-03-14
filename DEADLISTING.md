#### Chapter 8 of Mastering reverse engineering explained

#### Deadlisting

Reading a book called Mastering reverse engineering explained by Reginald Wong. There was some confusion from my side how certain addresses are calculated. That's why I made this write-up on how I look at it myself. I also got a bit confused with a "stack frame in a table", which did not look correct to me. So if anyone would like to explain it to me, feel free to reach out to me. More information about the book 

https://subscription.packtpub.com/book/networking-and-servers/9781788838849/1
https://www.amazon.com/Mastering-Reverse-Engineering-Re-engineer-ethical/dp/178883884X/



Download https://github.com/PacktPublishing/Mastering-Reverse-Engineering/blob/master/ch7/passcode.exe

First the program is asking for a password before it gets to scanf. The password is stored in the stack at ebp-28h. Then it compares if the string is 17 (11h) characters long. 

```assembly
.text:00401322                 call    _scanf
.text:00401327                 lea     eax, [ebp-28h]
.text:0040132A                 mov     [esp], eax      ; Str
.text:0040132D                 call    _strlen
.text:00401332                 cmp     eax, 11h
```

[scanf] https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/scanf-scanf-l-wscanf-wscanf-l
[strlen] https://docs.microsoft.com/en-us/dynamics-nav/strlen-function--code--text-



The code then jumps into a loop. Check certain addresses in the stack with the value e. Best is to know how to calculate these addresses statically.

```assembly
.text:004012E5                 mov     dword ptr [ebp-58h], 3
.text:004012EC                 mov     dword ptr [ebp-54h], 5
.text:004012F3                 mov     dword ptr [ebp-50h], 7
.text:004012FA                 mov     dword ptr [ebp-4Ch], 0Eh
.text:00401301                 mov     dword ptr [ebp-48h], 10h
.....
.....
.....
.text:0040133B                 mov     [ebp+var_5C], 5
.text:00401342                 mov     eax, [ebp+var_5C]
.text:00401345                 mov     [ebp+var_60], eax
.text:00401348                 cmp     [ebp+var_60], 0
.text:0040134C                 jle     short loc_40137A
.text:0040134E                 mov     eax, [ebp+var_60]
.text:00401351                 lea     edx, [ebp-8]
.text:00401354                 add     edx, [ebp+eax*4-5Ch]
.text:00401358                 mov     eax, edx
.text:0040135A                 sub     eax, 20h ; ' '
.text:0040135D                 cmp     byte ptr [eax], 65h ; 'e'
.text:00401360                 jz      short loc_401373
.....
.....
.....
.text:00401373 ; ---------------------------------------------------------------------------
.text:00401373
.text:00401373 loc_401373:                             ; CODE XREF: _main+A8↑j
.text:00401373                 lea     eax, [ebp+var_60]
.text:00401376                 dec     dword ptr [eax]
.text:00401378                 jmp     short loc_401348
```



.text:0040133B Move the value 5 into base pointer ebp+var_5C
.text:00401342 Move the value 5 into eax 
.text:00401345 Move the return value from eax into ebp+var_60

```assembly
.text:0040133B                 mov     [ebp+var_5C], 5
.text:00401342                 mov     eax, [ebp+var_5C]
.text:00401345                 mov     [ebp+var_60], eax
```

.text:00401348  Compare if the value at address `ebp+var_60` isn't `0`. 
.text:0040134C  Else jump less or equal (jle) to loc_40137A

```assembly
.text:00401348                 cmp     [ebp+var_60], 0
.text:0040134C                 jle     short loc_40137A
```

.text:0040134E Move the value at base pointer to eax

```assembly
.text:0040134E                 mov     eax, [ebp+var_60]
```

.text:00401351 Load Effective Address ebp-8 in edx. It loads the address of the location reference by the source operand to the destination operand. Edx (Extended Data Register) : params, data, math

```assembly
.text:00401351                 lea     edx, [ebp-8]
```

.text:00401354  Add the new calculated address of [ebp+eax*4-5Ch] to edx. 

​							To calculate the value of `eax*4-5Ch`,  
​							read it from right to left. For example (5Ch - 4h) * value of eax. 
​							Let's say that eax is 5 then 5Ch - 4h  * 5h = 10h is the new value from address `ebp-48h`. 
​							`.text:00401301  mov     dword ptr [ebp-48h], 10h`
​							Basically it's saying that `[ebp+eax*4-5Ch]`  is ebp -8h + [ebp -48h]. 
​							Between brackets means value of an address. But please correct me if I'm wrong.

​							Now we have `ebp-8+10h`. Read this from right to left, 
​							notice `ebp-8` is a negative number, 10h + -8h = `ebp+8` which is our new address. 

​							Simplified: 
​							`eax = 5;  edx = ebp-8+10h;  edx = ebp+8`

.text:00401358 move the value of edx which is `ebp+8h` into eax.

```assembly
.text:00401354                 add     edx, [ebp+eax*4-5Ch]
.text:00401358                 mov     eax, edx
```

.text:0040135A With our new address `ebp+8` subtracted `20h`
							From left to right, `20h` - `8h` = `18h`. which is ebp-18h

​							Simplified:
​							`from eax = 5;  eax = ebp+8-20h;  eax = ebp-18h`

```assembly
.text:0040135A                 sub     eax, 20h ; ' '
```

 .text:0040135D Compare byte points to value of eax if is 65h. eax = ebp-18h
.text:00401360 Jump if zero to location loc_401373

```assembly
.text:0040135D                 cmp     byte ptr [eax], 65h ; 'e'
.text:00401360                 jz      short loc_401373
```

.text:00401373 Load Effective Address var_60 into eax
.text:00401376 Decrease the value that points to address of [eax]
.text:00401378 Jump back to loc_401348 which is the beginning of the loop.

```assembly
.text:00401373                 lea     eax, [ebp+var_60]
.text:00401376                 dec     dword ptr [eax]
.text:00401378                 jmp     short loc_401348
```



We know that our stack starts at ebp-28. The loop checks if ebp-18, ebp-1a, ebp-21h, ebp-23 and ebp-25 has the value e. Counting backwards, little endian, we build the stack as followed.

```
Stack

ebp-18 e
ebp-19
ebp-1A e
ebp-1B
ebp-1C
ebp-1D
ebp-1E
ebp-1F
ebp-20
ebp-21 e
ebp-22
ebp-23 e
ebp-24
ebp-25 e
ebp-26
ebp-27
ebp-28
```

The next block in IDA read DWORD values from ebp-1A and ebp-25. Dword is 4bytes
Reading DWORD from `ebp-1Ah` is "ere". If the correct password is set.
Reading DWORD from `ebp-25h` is "ere ". Move the results into `ebp-2Ch`. Not entirely sure why but doing a AND Dword ptr [eax], 0FFFFFFh. The results `ere` stays the same. Basically this block we know that counting backwards from 1Ah and 25h it spells `ere`. 

```assembly
.text:0040137A                 mov     eax, [ebp-1Ah]
.text:0040137D                 and     eax, [ebp-25h]
.text:00401380                 mov     [ebp-2Ch], eax
.text:00401383                 lea     eax, [ebp-2Ch]
.text:00401386                 and     dword ptr [eax], 0FFFFFFh
.text:0040138C                 lea     eax, [ebp-2Ch]
.text:0040138F                 mov     dword ptr [esp+4], offset Str2 ; "ere"
.text:00401397                 mov     [esp], eax      ; Str1
.text:0040139A                 call    _strcmp
.text:0040139F                 test    eax, eax
```

```
Stack update

ebp-18 e
ebp-19 r
ebp-1A e
ebp-1B
ebp-1C
ebp-1D
ebp-1E
ebp-1F
ebp-20
ebp-21 e
ebp-22
ebp-23 e
ebp-24 r
ebp-25 e
ebp-26
ebp-27
ebp-28
```

The next block is checking if `ebp-22` and `ebp-1E` have a sum of 40h. We now know that both have the value of 20h and 20h is space in the ascii table.

```
.text:004013AE                 movsx   eax, byte ptr [ebp-22h]
.text:004013B2                 movsx   edx, [ebp+var_1E]
.text:004013B6                 add     eax, edx
.text:004013B8                 cmp     eax, 40h ; '@'
.text:004013BB            
```

```
Stack update

ebp-18 e
ebp-19 r
ebp-1A e
ebp-1B
ebp-1C
ebp-1D
ebp-1E SPACE
ebp-1F
ebp-20
ebp-21 e
ebp-22 SPACE
ebp-23 e
ebp-24 r
ebp-25 e
ebp-26
ebp-27
ebp-28
```

Counting backward from `ebp-28h` check if the value is `duA`

```
.text:004013BD                 mov     eax, [ebp-28h]
.text:004013C0                 and     eax, 0FFFFFFh
.text:004013C5                 cmp     eax, 'duA'
```

```
Stack update

ebp-18 e
ebp-19 r
ebp-1A e
ebp-1B
ebp-1C
ebp-1D
ebp-1E SPACE
ebp-1F
ebp-20
ebp-21 e
ebp-22 SPACE
ebp-23 e
ebp-24 r
ebp-25 e
ebp-26 d
ebp-27 u
ebp-28 A
```

Checks from `ebp-1Dh` if it contains `caF`

```assembly
.text:004013CC                 mov     eax, [ebp-1Dh]
.text:004013CF                 and     eax, 0FFFFFFh
.text:004013D4                 cmp     eax, 'caF'
```

```
Stack update

ebp-18 e
ebp-19 r
ebp-1A e
ebp-1B c
ebp-1C a
ebp-1D F
ebp-1E SPACE
ebp-1F
ebp-20
ebp-21 e
ebp-22 SPACE
ebp-23 e
ebp-24 r
ebp-25 e
ebp-26 d
ebp-27 u
ebp-28 A
```

Check if from `ebp+var_20` has the value `ts`

```assembly
.text:004013DB                 movzx   eax, [ebp+var_20]
.text:004013DF                 cmp     eax, 'ts'
```

```
Stack update

ebp-18 e
ebp-19 r
ebp-1A e
ebp-1B c
ebp-1C a
ebp-1D F
ebp-1E SPACE
ebp-1F t
ebp-20 s
ebp-21 e
ebp-22 SPACE
ebp-23 e
ebp-24 r
ebp-25 e
ebp-26 d
ebp-27 u
ebp-28 A
```

Now imagine the stack falling over from the top which gives us the password : `Audere est Facere`