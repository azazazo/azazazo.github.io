+++
title = "Upsolving two pwn challenges from last year"
date = "2025-01-06T18:06:12+08:00"
author = "azazo"
description = "my new years resolution is get better at pwn"
tags = ["ctf", "writeup"]
showFullContent = false
readingTime = false
hideComments = false
+++

# Introduction

Happy (belated) new year. Here are writeups for two pwn challenges I didn't manage to solve last year.

# IrisCTF 2025 - Checksumz

I wrote [a writeup for IrisCTF last year](https://blog.azazo.me/posts/irisctf25/), and in it I lamented about how I didn't manage to solve a kernel pwn challenge. Well, I finally got around to learning enough kernel pwn so that I could solve it.

These two websites were very helpful:
- https://blog.elmo.sg/posts/imaginary-ctf-2023-kernel-pwn
- https://pawnyable.cafe/linux-kernel/ (in Japanese)[^1]

so check them out if you want to learn more about kernel pwn.

I'll be writing this writeup as if I was explaining the solution to one year ago me, so some parts might be over/underexplained. I am also not an expert in kernel pwn, so there may be some mistakes here and there. Sorry about that.

## What is kernel pwn?

Kernel pwn differs from "normal" (userland) pwn in some ways. Most of the time, in userland pwn, we are given a program that contains some vulnerability, and have to exploit it to call some `win()` function that prints the flag, or achieve arbitrary command execution so we can `cat flag.txt` ourselves. However, with kernel pwn, since we are interacting with a VM, we can _already_ execute arbitrary commands! Our main goal in kernel pwn will mostly be to achieve _privilege escalation_, so we can run arbitrary commands as `root` instead of a lowly user with restricted permissions.

Another significant difference is the way we interact with the vulnerable program. In userland pwn, most of the time the program can be ran directly and interacted with through stdin/stdout. In kernel pwn, the vulnerable program is a _module_ that is loaded into the kernel during startup, that we can't just "run". Instead, we have to write code that interfaces with the kernel module, then run it on the VM. This also makes debugging our exploits harder, as we can't just `gdb` the vulnerable program itself.

Anyways, with all that being said, `checksumz` is quite a beginner-friendly challenge, in the sense that it details how to run the VM and get our exploit in it. It also helpfully provides us with an `attach.gdb` that we can use to debug our exploit in the VM (though it didn't work that well for me).

## The challenge

The source code of the kernel module is provided, so thankfully no reversing is needed:

<details>
<summary>chal.c</summary>

```c
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This kernel module has serious security issues (and probably some implementation
 * issues), and might crash your kernel at any time. Please don't load this on any
 * system that you actually care about. I recommend using a virtual machine for this.
 * You have been warned.
 */

#define DEVICE_NAME "checksumz"
#define pr_fmt(fmt) DEVICE_NAME ": " fmt

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uio.h>
#include <linux/version.h>

#include "api.h"

static void adler32(const void *buf, size_t len, uint32_t* s1, uint32_t* s2) {
     const uint8_t *buffer = (const uint8_t*)buf;
 
     for (size_t n = 0; n < len; n++) {
        *s1 = (*s1 + buffer[n]) % 65521;
        *s2 = (*s2 + *s1) % 65521;
     }
}

/* ***************************** DEVICE OPERATIONS ***************************** */

static loff_t checksumz_llseek(struct file *file, loff_t offset, int whence) {
	struct checksum_buffer* buffer = file->private_data;

	switch (whence) {
		case SEEK_SET:
			buffer->pos = offset;
			break;
		case SEEK_CUR:
			buffer->pos += offset;
			break;
		case SEEK_END:
			buffer->pos = buffer->size - offset;
			break;
		default:
			return -EINVAL;
	}

	if (buffer->pos < 0)
		buffer->pos = 0;

	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return buffer->pos;
}

static ssize_t checksumz_write_iter(struct kiocb *iocb, struct iov_iter *from) {
	struct checksum_buffer* buffer = iocb->ki_filp->private_data;
	size_t bytes = iov_iter_count(from);

	if (!buffer)
		return -EBADFD;
	if (!bytes)
		return 0;

	ssize_t copied = copy_from_iter(buffer->state + buffer->pos, min(bytes, 16), from);

	buffer->pos += copied;
	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;
	
	return copied;
}

static ssize_t checksumz_read_iter(struct kiocb *iocb, struct iov_iter *to) {
	struct checksum_buffer* buffer = iocb->ki_filp->private_data;
	size_t bytes = iov_iter_count(to);

	if (!buffer)
		return -EBADFD;
	if (!bytes)
		return 0;
	if (buffer->read >= buffer->size) {
		buffer->read = 0;
		return 0;
	}

	ssize_t copied = copy_to_iter(buffer->state + buffer->pos, min(bytes, 256), to);

	buffer->read += copied;
	buffer->pos += copied;
	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return copied;
}

static long checksumz_ioctl(struct file *file, unsigned int command, unsigned long arg) {
	struct checksum_buffer* buffer = file->private_data;

	if (!file->private_data)
		return -EBADFD;
	
	switch (command) {
		case CHECKSUMZ_IOCTL_RESIZE:
			if (arg <= buffer->size && arg > 0) {
				buffer->size = arg;
				buffer->pos = 0;
			} else
				return -EINVAL;

			return 0;
		case CHECKSUMZ_IOCTL_RENAME:
			char __user *user_name_buf = (char __user*) arg;

			if (copy_from_user(buffer->name, user_name_buf, 48)) {
				return -EFAULT;
			}

			return 0;
		case CHECKSUMZ_IOCTL_PROCESS:
			adler32(buffer->state, buffer->size, &buffer->s1, &buffer->s2);
			memset(buffer->state, 0, buffer->size);
			return 0;
		case CHECKSUMZ_IOCTL_DIGEST:
			uint32_t __user *user_digest_buf = (uint32_t __user*) arg;
			uint32_t digest = buffer->s1 | (buffer->s2 << 16);

			if (copy_to_user(user_digest_buf, &digest, sizeof(uint32_t))) {
				return -EFAULT;
			}

			return 0;
		default:
			return -EINVAL;
	}

	return 0;
}

/* This is the counterpart to open() */
static int checksumz_open(struct inode *inode, struct file *file) {
	file->private_data = kzalloc(sizeof(struct checksum_buffer), GFP_KERNEL);

	struct checksum_buffer* buffer = (struct checksum_buffer*) file->private_data;

	buffer->pos = 0;
	buffer->size = 512;
	buffer->read = 0;
	buffer->name = kzalloc(1000, GFP_KERNEL);
	buffer->s1 = 1;
	buffer->s2 = 0;

	const char* def = "default";
	memcpy(buffer->name, def, 8);

	for (size_t i = 0; i < buffer->size; i++)
		buffer->state[i] = 0;

	return 0;
}

/* This is the counterpart to the final close() */
static int checksumz_release(struct inode *inode, struct file *file)
{
	if (file->private_data)
		kfree(file->private_data);
	return 0;
}

/* All the operations supported on this file */
static const struct file_operations checksumz_fops = {
	.owner = THIS_MODULE,
	.open = checksumz_open,
	.release = checksumz_release,
	.unlocked_ioctl = checksumz_ioctl,
	.write_iter = checksumz_write_iter,
	.read_iter = checksumz_read_iter,
	.llseek = checksumz_llseek,
};


/* ***************************** INITIALIZATION AND CLEANUP (You can mostly ignore this.) ***************************** */

static dev_t device_region_start;
static struct class *device_class;
static struct cdev device;

/* Create the device class */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static inline struct class *checksumz_create_class(void) { return class_create(DEVICE_NAME); }
#else
static inline struct class *checksumz_create_class(void) { return class_create(THIS_MODULE, DEVICE_NAME); }
#endif

/* Make the device file accessible to normal users (rw-rw-rw-) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static char *device_node(const struct device *dev, umode_t *mode) { if (mode) *mode = 0666; return NULL; }
#else
static char *device_node(struct device *dev, umode_t *mode) { if (mode) *mode = 0666; return NULL; }
#endif

/* Create the device when the module is loaded */
static int __init checksumz_init(void)
{
	int err;

	if ((err = alloc_chrdev_region(&device_region_start, 0, 1, DEVICE_NAME)))
		return err;

	err = -ENODEV;

	if (!(device_class = checksumz_create_class()))
		goto cleanup_region;
	device_class->devnode = device_node;

	if (!device_create(device_class, NULL, device_region_start, NULL, DEVICE_NAME))
		goto cleanup_class;

	cdev_init(&device, &checksumz_fops);
	if ((err = cdev_add(&device, device_region_start, 1)))
		goto cleanup_device;

	return 0;

cleanup_device:
	device_destroy(device_class, device_region_start);
cleanup_class:
	class_destroy(device_class);
cleanup_region:
	unregister_chrdev_region(device_region_start, 1);
	return err;
}

/* Destroy the device on exit */
static void __exit checksumz_exit(void)
{
	cdev_del(&device);
	device_destroy(device_class, device_region_start);
	class_destroy(device_class);
	unregister_chrdev_region(device_region_start, 1);
}

module_init(checksumz_init);
module_exit(checksumz_exit);

/* Metadata that the kernel really wants */
MODULE_DESCRIPTION("/dev/" DEVICE_NAME ": a vulnerable kernel module");
MODULE_AUTHOR("LambdaXCF <hello@lambda.blog>");
MODULE_LICENSE("GPL");
```

</details>

That's pretty long, so let's break it down. The code we're looking at here registers a _character device_ at `/dev/checksumz`, and defines several methods for interacting with it. 

# ICO 2025 - studystudystudy




[^1]: i gotta put that jlpt n2 certification to use somehow