# Project goal

SK Zero copy project
This project is a very fast packet receive from kernel space or send from userspace.
Both are implemented as a single kernel module for Linux.

This project have the same goal with netmap.
you can check the link http://info.iet.unipi.it/~luigi/netmap/ for the project goal.

I think my design is more easy to use.

Please check the kernel patch linux-2.6.32-504.3.3.el6-zcopy.patch
I hope kernel upstream can merge or generate a standard for package zero copy.

Here is another project for you want to compile as a module.
https://github.com/Super-King/sk_zcp_module

# Dir introduce

driver: including zero copy driver and kernel patch.

example: including send forward and recive sample program.

include: using for application head file.

lib:     using for application lib file.

# Test ENV
centOS 6.5 kernel linux-2.6.32-504.3.3.el6 patch it then test passed.
for e1000 driver you needn't change anyting but please reload e1000 drver before test it.

# Usage for reload e1000
rmmod e1000
modprobe e1000 copybreak=0 //disable copybreak

