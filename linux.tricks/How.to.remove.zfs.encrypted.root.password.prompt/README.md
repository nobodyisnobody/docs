### How to remove password prompt for a ZFS encrypted root ubuntu 22.04 installation.

You can change the method for entering a key on zfs, and instead of password prompt, to use a file as a key.

But it has to be available at the time of booting, and before root is mounted so..

At this time you only have a minimal root filesystem from initrd `initramf`s mounted,

with some modules and configuration files needed to boot..

I've seen some people trying to resolve the issue, via using an usb key, and add additional configure script in `initramfs` to mount it, and read the key file from the usb key..

But I did not like this solution..

So I search what files were copied during the `initramfs` creation, and when using zfs root, all the directory `/etc/zfs` seems to be copied to the newly created `initramfs`, each time ubuntu call `update-initramfs`

So it makes a good directory candidate to put a key in , that will be used to unlock our encrypted zfs root partition.



so here is the method:

**1. we create a temporary key in /etc/zfs/tempo.key:**

```bash
sudo dd if=/dev/random bs=1 count=32 of=/etc/zfs/tempo.key
```



**2. we update initramfs to integrate key in the the newly re-created initramfs**

```bash
sudo update-initramfs -u -k all
sudo update-grub
```



**3. we change authentification method for unlock zfs encrypted root (rpool):**

```bash
sudo zfs change-key -o keylocation=file:///etc/zfs/tempo.key -o keyformat=raw rpool
```



then we verifiy that the key is in the initramfs before rebooting (use the correct /boot/initrd.. name):

```bash
lsinitramfs /boot/initrd.img-5.15.0-52-generic | egrep tempo
```

the output should be `etc/zfs/tempo.key`

if it's correct, now we have finished, the next time you will reboot you will boot your zfs root encrypted without entering a passwod, you can eventually like me start your computer with wakeonlan,

connect to it, do what you want, shut it down remotely...



**finally, to revert to a prompt password authentification method at boot:**

```bash
sudo zfs change-key -o keylocation=prompt -o keyformat=passphrase rpool
```

you will be asked for a password, and next time you will reboot, the password prompt authentification will be back.

**you can verify your actual setup with the command:**

```bash
zfs get keylocation,keyformat,encryption rpool
```

