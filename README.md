# Hey! I'm Filing Here

In this lab, I successfully implemented the following TODO

## Building

In order to Build you must first run:

make

you should then build a directory to mount the filesystem by with the following:

mkdir mnt

## Running

after this you must then run:

./ext2-create

in order to create cs111-base.img

after this you must get the program runnning by mounting the file system with the following command:

sudo mount -o loop cs111-base.img mnt

next run:

fsck.ext2 cs111-base.img

to check the validity of your filesystem

and then:

dumpe2fs cs111-base.img 

in order to get the filesystem's information

from here you can acces the file system due to mounting it as a loop


## Cleaning up

After running the program you must unmount and clean up the used files with the following commands:

sudo umount mnt
rmdir mnt
make clean

