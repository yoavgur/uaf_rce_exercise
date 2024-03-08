# Exercise.exe Research

I'll try log my progress and thoughts here regarding my advancement in the Exercise.exe exercise :D

Note: Also attached are my idb and exploitation python scripts, of which attack3.py is the one that works.


### What Does The Program Do?
So from just running the program and the python script it looks like it's a simple server that binds to a port and prints out whatever it gets (although it does seem to limit you to one message)

Let's start by looking at the python script to understand this a bit better.

So it indeed looks like a somewhat shitty server that enables chat between the different clients. I played a bit with the python code to make it work a bit better. Looks like you can:
* Connect
* Update name
* Get name
* Send message
* Receive message

The server seems to get commands and differentiate between them based on the first 7 bytes, which are:
* NEWNAME - update your name
* READNAM - get your name
* TOSERVR - send the actual text

Seems simple enough. Other than the general bugginness it seems to handle things pretty well (doesn't cause problems when sending text before set newnam), weird things
that I saw include:
* Sometimes when connecting to the server, if you have a short name it seems to add more characters from somewhere (are we reading
from its memory?). For example, here I gave the name 'p' and then my first message was test and the server printed: "message: <p\LAPTOP┤♠VτE‼> test". This seems like a promising lead.
* The server sometimes sends me back the messages and sometimes it doesn't, I think it's on a per session basis. 

In terms of how the messages themselves look, they look like this:
* 8 bytes - 7 bytes of message identifier then 1 null terminating byte
* 4 bytes - length of the content of the message
* However many bytes of the actual content

Let's take a look at how the server-side looks by opening it up using IDA.

### Analyzing The Server
So after managing to get dark mode on IDA to work, and setting up wsl (cause using tmux while working is da best), I loaded up the program in IDA.
The first thing it asksed me was whether I wanted to load debug symbols, and it then showed me the path where the program was compiled.
This was interesting since the path contained the words `use_after_free`, which I know is a common type of bug that can taken advantage of when looking
for vulnerabilities. It seemed a bit weird that the creators would forget to remove the debug information, so either this an intentional clue, or an intentional
decoy (or just a mistake :D). Either way I'll keep it mind, but I won't limit myself to just that.

##### Getting a Clearer Picture
The first thing I did was to try to understand the general flow of the entire program as well as possible. I must say that I really enjoyed this part, it was kind of
like solving a puzzle bit by bit.

I started by looking at the strings and comparing them to strings that I know that the server prints, like the welcome message, the new client message etc.
I then looked at where those strings are reference and pretty quickly managed to draw an outline of roughly which functions exist and what they do.
These included the main_loop, receiving a message, updating name and more.

The next thing I noticed was that most of the interesting functions weren't called directly, but were stored in a global struct (which made understanding where they're called from a bit harder). I xref'd that global struct and saw that it was used in some kind of init func which stores more fields in some kind of object, as well as the pointers to those functions. This explains a lot of the references I saw in other places. I then added a struct type to tell IDA which functions were
which in the global struct, which made understanding when these functions are called a lot easier. I will say that I wish that I could then tell IDA to find me all the usages of those function pointers. This is probably possible using some kind of a plugin or using their built in python features, but since the code isn't that big it'll probably be faster not to do that. 
After all of that I understood what the main object was and what its fields were.

Those structs look like this:

```
struct m_conn_funcs_t {
    void *destroy_conn_obj;
    void *recv_and_handle_message;
    void *send_message;
    void *maybe_update_name;
    void *print_msg_and_maybe_send_resp;
    void *handle_admin_message;
    void *unauth_handle_admin_message;
    void *read_name;
    void *send_resp_not_used2;
};

struct m_conn_obj_t {
    struct m_conn_funcs_t *vftable;
    int socket_fd;
    int obj_index;
    int is_admin;
    int username_len;
    char *username;
};
```

##### Finding Primitives
At this point, now that I have a sense for how the program works I would like to turn my attention to finding mistakes here.

My first instinct is to look for any buffer overflows mistakes (cause they would seem natural here), and any resource allocation mistakes (double close, use after free), since there's a lot of opening / allocating and closing / freeing of resources.

**Off By Two**
This is something small of little consequence, but I noticed that when crafting a response, the function checks `if (m_content_len + m_local_this->username_len + 4 <= 1024)`, but it doesn't take the gt and st signs that it adds into consideration (<name>). This doesn't matter much though I think cause it just means that message will be cut short by a little bit.

**Resource Freeing**
There are two places where I thought to look for in this situation - object freeing and name freeing.

The function that frees the connection objects seems to not have any problems, except for the fact that you can pass a flag which instructs the function not to actually free the memory (only deinit the object). This is weird and I don't know why they would use it, especially since I can't find any instances where the function is called with that flag as false.
But, the process of freeing an object and closing its fd does seem a bit convoluted. It involved an array of object pointers and fds, and when a bad response is received the fds are all moved one down in the array to avoid any gaps. I haven't gone over this logic too much yet, but it could definitely be a place where double closes or use after frees could occur.

The function that updates users' usernames does appear to be more promising though. The thing I noticed first was that the freeing and allocating occur in two different places in the code (which could mean that one section could be reached while avoiding the other). The other thing I noticed was that after freeing the username, the function doesn't then set it to equal NULL, which could be a problem because later on it won't be able recognize whether the memory has been deallocated or not.
The bug I found was that the username validation occurs after having freed the username. That means that we could trigger a scenario where the username is freed, then the function would fail because of an invalid input, and then the server would continue to work normally. This could be triggered in such a way:
* Connect and set name
* Update name to name of len 0 or above 64
After this the username pointer would point to deallocated memory, but would still be used - use after free!

I then tried it out and was dissapointed to see that the process didn't crash. I thought that it would trigger a segfault, but I guess since the memory is still within a page that still belongs to the process it doesn't cause a crash. I do know though that these kinds of bugs can enable you to leak resources by having another part of the program allocate memory and receive the memory that the original one still holds a pointer to.
I quickly POCd this by triggering the bug using one client, adding another client, and seeing that the name of the original client changed to the name of the new client. Cool! Now I need to understand how I can leverage this (now that I think of it, this could also trigger a double free).

---------------------------------------------------

Okay I think I figured out a way to use this. The user field is max 64 bytes, and the obj field is 24 bytes. That means that if I initially allocate a 24 (or larger probably) byte long name, then free it, the next connection object I create will be on that same memory. I could then have full control of all of that object's fields!!
The first thing I thought that I could do with that was to change my is_admin flag to true, but then I realised I could also change the function pointer struct pointer to point somewhere else which I could control (which I guess would be the rest of the struct), and that function could point to somewhere malicious. Two dereferences occur here (once to the struct and once to the function), so I would need to know the addresses of everything so that I could point to the write places.
I think I'll just start with a making the program crash, and then maybe I'll try to do a quick win on the is_admin front just cause I'm curious :D.

Now that I think of it, the server sends the name of the user every time it receives a message from him! That means we could send a message from our initial client and get a dump of the 2nd clients object!


### Exploitation

##### POC
Following what I wrote above, I tried to exploit the vulnerability I found. The easiest thing would be to make the process crash by overriding the function pointer struct pointer, causing the process to jump to and try to execute random memory. Sadly, this just wouldn't work. I tried different initial name lengths (which translate to different freed blocks), but nothing would work - which was especially strange since I could get it to work with the new agent's name being allocated to the old agent's name (as described above).

I thought that maybe the right thing to do was to debug the program dynamically, so I quickly learned how to do it with IDA (because using their breakpoints is **amazing**).
Sadly, this did not help me much either. I just saw that the new agent's object got allocated a different address on the heap. 

After a while of not understanding why this is happening, I came to the realisation that this probably does make sense. The heap is probably a mess of allocations and de-allocations, and there are for sure other places on the heap that qualify for allocating the new object on. My best guess for the solution would then be to create one agent which could free, read, and update its name field, and then create and destroy a ton of other agents with the hope that one will be allocated to where my agent's name points to.

I attempted an initial implementation of this by just freeing, creating a new connection, and writing random stuff over it, over and over again in a loop. This did lead to a crash! Super cool! I then opened windows event viewer cause I assumed I'd be able to see the reason for the crash there (similarly to dmesg I suppose), and it did in fact say the Exercise.exe crashed due to Access Violation!

So now that we proved that we can use this use-after-free to be able to edit the contents of a connection object, we need to think of how this could lead to an actual exploit.
This took me a number of attempts to do successfully, each time realizing that the attempt is flawed.

##### Attempt 1 - Just Jump To The Heap
The first direction I decided to take was to write a shellcode on the heap and jump to it. I could do this in the following steps:
1. Create conn_obj 1 and trigger use-after-free
2. Create conn_obj 2 which is allocated in the address of conn_obj 1's name
3. Write a shellcode to conn_obj 2's name, which would include - first the address of the following 4 bytes, then an actual shellcode. You'll see why next.
4. Use conn_obj 1 to change the pointer to the function pointer struct to point to conn_obj 2's name (which holds the previously mentioned shellcode). Now, when when of those functions will be called it'll first go to the beginning of our shellcode, where it'll expect a pointer to a function. Here we prepared a pointer to the rest of the shellcode, which will then be triggered.

To see how I did all of this you can look at attack.py - the gist of is that using conn_obj 1 I put the last four bytes of conn_obj_2 (which are the pointer to its username) instead of the first 4 bytes (which are a pointer to the function pointer struct). Also, in order to know whether conn_obj_2 was allocated to where I wanted it to be, I used read_name to see what the first 4 bytes of conn_obj_1's name was. If they were the address of the function pointer struct, I knew that the object was allocated there.

This obviously didn't work... I didn't think of it right away at the time, but doing this hasn't been possible for at least the past 20 years due to mitigations that don't allow you to execute sections which have no reason to be executable. Makes sense :D. But, I did prove that I could control the instruction pointer and make it go wherever I wanted it to. To prove this, I made to jump to address 0x1337, saw that it crashed, and saw that the event log said that the process crashed because it jump to that address. Cool.

##### Attempt 2 - Lets Read and Write Everywhere
This may be less so an attempt and more so a stage. At this point I wasn't sure how I could leverage this vulnerability to at actual exploit, but I was pretty sure that I could do some cool stuff with it. My goal here was to be able to read, write, and jump to any address, and figure out what to do with that later.

There isn't that much new here but the idea is this:
* Read - in order to read an address, I can just use conn_obj_1 to overwrite conn_obj_2's name pointer. I can then use the read_name function to read up to 64 bytes of wherever it's pointing to. I could then wrap that in a function that can read however much you want from wherever.
* Write - same thing as read, but use the update name function, which if given a name of the same len as before, just writes to the address instead of freeing and re-mallocing.
* Jump - same as explained in Attempt 1.

Now that we have all of these primitives, we'll be better suited for managing to run code. See file attack2.py for the implementations.

##### Attempt 3 - Frustration and Success
So now that we have basically anything an attacker could ask for (read,write and jump), let's understand what's even possible with today's mitigations.

The problems are that we can't write to an executable segment, but cant execute a writable segment. The way we can deal with these problems is by using code from executable sections.
The more innocent usage of this would be to call an existing function - we could use functions within kernel32.dll for example to run a cmd command (you could also call a function that would make the heap executable for example). The more advance usage would be to be able to create a ROP chain that would do what we want.

What's a ROP chain? Generally, it's where you take a bunch of gadgets (small sections of assembly code which usually contain a single instruction and a ret) and chain them together to run the code that your shellcode would've run. This is a really clever concept, mainly because it seems very hard to protect against it.

The main hurdle I encountered here was that we don't have the address of the stack and exactly where the current stack frame is when we want to run the exploit. 
As far as I cant tell, this seems to be a problem in terms of creating a ROP chain since in the flow where I trigger a jump to an address, the return address is pushed to the 
stack. That means that I can trigger execution of a single gadget, which would then return to where it was called from, which isn't where I wrote my shellcode, but is in fact the code section. There's probably a way around this, or at the very least a way to leak the stack address somehow, but I decided to try a simpler route, which would be to call a function in kernel32.dll - WinExec.

Although there's a similar problem here - which is that I would need to push the function arguments to the stack - I decided to postpone thinking about it until later.
For now I wanted to understand how to find the address of the function.

I read a bit about kernel32.dll and how programs used it, and understood that it's always loaded at the same address (this is probably not always true, but maybe it is. I could see why this would make sense - programs could always know where to find it, but it also seems dangerous for the reason that I can use it in the way that I am now. I guess I expected some kind of ASLR to load this to a random address each time).
I then read a bit about how to know where a dll's exported functions, which is something I for sure have already learned but forgotten.

Using a cool program caller 'peview.exe', I opened up kernel32.dll and found it's relative address, to which I could add kernel32.dll's base address to know where to jump to. This totally worked, but I also realized that doing this wasn't quite right since it limited my exploit to working only on that specific version of kernel32.dll. To solve this, I found a useful article online which guided me through all the different offsets and addresses I needed in order to find a function's address given its name.

So now that I have a function which automatically and dynamically finds me WinExec's address, the only thing I need to understand is how to push the arguments on the stack. For this, I went back to IDA to see if I could find a place where I could leak the stack address or anything similar.
At this point, I realized that the functions that I'm overwriting their addresses are already sending arguments to the functions that they're calling - and thus pushing those arguments on the stack - and that I control some of those arguments!

To test exactly how these arguments would look to WinExec, I dynamically debugged the process and manually changed the function address of 'print_msg_and_send_to_clients' to WinExec, and put a breakpoint on it. I then sent a message called 'test' and saw in my breakpoint that the WinExec function got the message buffer and message len as arguments! This is amazing because WinExec expects a string and an int as its arguments, so I really got lucky here.

So what do I need to pass to WinExec? The string is the name of the program to run, and the int is the way to run it. According to the documentation I want the integer to be equal to 10 for normal behavior. The problem is that the value passed to the function is the length of the message, so while I could send a message shorted than 10 bytes and pad it to ten, I can't send a longer message. This saddens me somewhat as I wanted the program that I ran to be mspaint.exe, which is 11 bytes long. We'll just have to settle for calc.exe :D.

At this point I got stuck on a stupid mistake of mine where I thought I overwrote the 'print_msg_and_send_to_clients' function, but really I overwrote the 'handle_msg' function (which is the function that has the switch case between the different commands). Because of this, the arguments that I thought were supposed to get to WinExec weren't getting to it. 
To debug this I both used IDA for dynamic debugging (again, amazing), sysinternals for creating process dumps when they crash, and windbg for analyzing those dumps. After I found the bug I finally managed to make the exploit work. The final flow was this:

* Create conn_obj_1
* Free and allocate new objects repeatedly until detecting that an object (conn_obj_2) was allocated to the freed address
* Find WinExec's address
* Read the function pointer struct's contents and write them to conn_obj_2's name, after having edited the 'print_msg_and_send_to_clients' pointer to point to WinExec's address
* Edit conn_obj_2's first four bytes to point to where conn_obj_2's name points to, which is where our edited function pointer struct is
* Have conn_obj_2 send the message 'calc.exe' padded to ten bytes (with NULL bytes)
* Success! (This has so far always continued graciously since we don't do anything too messed up here. Bonus!)


### Thoughts
There are a bunch of things that I would've done had I had more time, like understanding how to make ROP work in this situation, or being able to call kernel32.dll functions more generically without the limitations specified. I'm also not 100% sure how portable this exploit is because, as I said previously, I would think that addresses such as the function pointer struct or kernel32.dll loading address would be randomized. Although, it doesn't seem too hard to be able to deal with this if it was in fact the case.
To understand where the function pointer struct is you'd just go through the allocation de-allocation process and see which address came up most often. I'm also sure there are heuristics for finding where the kernel32.dll is loaded, shouldn't be too hard when we've got unrestricted reading capability.

Hope you enjoyed reading :).


.
.
.
.


P.S.
The flag was 'FLAG{ADMIN-AFTER-FREE}' ;)


### Updates
So, after I tried to run the exploit on my girlfriend's computer I realized that the addresses are in fact randomized, but per boot.

I wanted to find a quick solution to this, so when checking whether a conn_obj was allocated to the user pointer of a our conn_obj, instead of checking if its first 4 bytes are equal to the function pointer struct address, I just check that its different from "a"*24 (which is the name I set) and different from 0 and 1 (which are values that tended to appear there).

I also wanted to find a quick solution to finding kernel32.dll, so I implemented something similar to finding WinExec. I find our process's loading address by understanding what the address of the function pointer struct is and decreasing the constant offset from it, and look at its import table.
My assumption was that this table would be overwritten with relevant values upon load, which looks to be true. The exe uses a number of functions from kernel32.dll, and when looking reading what their address was I saw that it did in fact point to the memory space of kernel32.dll. 

The way I'd want to calculate this would be to find a function in the import table, say GetLastError, get its address, and subtract from that address the offset that I know should be the offset from the beginning of kernel32.dll. The problem here is that that makes it kernel32.dll version dependant, which we explicitly wanted to avoid. 

As a quick work-around for now, I noticed that loaded dlls are 0x10000 aligned. To roughly caluclate the address I'll just decrease the known function offset, but decrease it less a certain number, then shift left and back right 16 bits to align to 0x10000. That way, if a bunch of functions were added between my version and another, we won't decrease too much and round 0x10000 too far down, and if there are fewer functions than we expect then we'll stay in that range (unless its 0x10000 / 4 functions).

This is not ideal, but it seems to have worked reaonably well on my machine as well as my girlfriend's.

