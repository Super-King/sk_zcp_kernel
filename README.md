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

