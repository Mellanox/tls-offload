/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <linux/module.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <uapi/linux/mlx5/accel_tools.h>
#include "tools_char.h"

#define CHUNK_SIZE (32 * 1024)

static int major_number;
static struct class *char_class;
struct ida minor_alloc;

struct file_context {
	struct mlx_accel_tools_dev *sb_dev;
	enum mlx_accel_access_type access_type;
};

static int tools_char_open(struct inode *inodep, struct file *filep)
{
	struct mlx_accel_tools_dev *sb_dev =
			container_of(inodep->i_cdev,
				     struct mlx_accel_tools_dev,
				     cdev);
	struct file_context *context;

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	context->sb_dev = sb_dev;
	context->access_type = MLX_ACCEL_ACCESS_TYPE_DONTCARE;
	filep->private_data = context;
	atomic_inc(&sb_dev->open_count);
	dev_dbg(&sb_dev->accel_device->hw_dev->pdev->dev,
		"mlx tools char device opened %d times\n",
		atomic_read(&sb_dev->open_count));
	return 0;
}

static int tools_char_release(struct inode *inodep, struct file *filep)
{
	struct file_context *context = filep->private_data;

	WARN_ON(atomic_read(&context->sb_dev->open_count) < 1);
	atomic_dec(&context->sb_dev->open_count);
	dev_dbg(&context->sb_dev->accel_device->hw_dev->pdev->dev,
		"mlx tools char device closed. Still open %d times\n",
		atomic_read(&context->sb_dev->open_count));
	kfree(context);
	return 0;
}

static ssize_t tools_char_read(struct file *filep, char __user *buffer,
			       size_t len, loff_t *offset)
{
	int ret = 0;
	void *kbuf = NULL;
	struct file_context *context = filep->private_data;

	dev_dbg(&context->sb_dev->accel_device->hw_dev->pdev->dev,
		"mlx tools char device reading %lu bytes at 0x%llx\n",
		len, *offset);

	if (len < 1)
		return len;
	if (len > CHUNK_SIZE)
		len = CHUNK_SIZE;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out;
	}
	ret = mlx_accel_tools_mem_read(context->sb_dev, kbuf, len, *offset,
				       context->access_type);
	if (ret <= 0)
		goto out;
	*offset += ret;
	if (copy_to_user(buffer, kbuf, len)) {
		pr_err("Failed to copy data to user buffer\n");
		ret = -EFAULT;
		goto out;
	}
out:
	kfree(kbuf);
	return ret;
}

static ssize_t tools_char_write(struct file *filep, const char __user *buffer,
				size_t len, loff_t *offset)
{
	int ret = 0;
	void *kbuf = NULL;
	struct file_context *context = filep->private_data;

	dev_dbg(&context->sb_dev->accel_device->hw_dev->pdev->dev,
		"mlx tools char device writing %lu bytes at 0x%llx\n",
		len, *offset);

	if (len < 1)
		return len;
	if (len > CHUNK_SIZE)
		len = CHUNK_SIZE;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out;
	}
	if (copy_from_user(kbuf, buffer, len)) {
		pr_err("Failed to copy data from user buffer\n");
		ret = -EFAULT;
		goto out;
	}

	ret = mlx_accel_tools_mem_write(context->sb_dev, kbuf, len, *offset,
					context->access_type);
	if (ret <= 0)
		goto out;
	*offset += ret;
out:
	kfree(kbuf);
	return ret;
}

static loff_t tools_char_llseek(struct file *filep, loff_t offset, int whence)
{
	loff_t new_offset;
	struct file_context *context = filep->private_data;
	u64 max = mlx_accel_core_ddr_base_get(context->sb_dev->accel_device) +
		  mlx_accel_core_ddr_size_get(context->sb_dev->accel_device);
	new_offset = fixed_size_llseek(filep, offset, whence, max);
	if (new_offset >= 0)
		pr_debug("tools char device seeked to 0x%llx\n", new_offset);
	return new_offset;
}

long tools_char_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct file_context *context = filep->private_data;
	struct mlx_accel_fpga_query query;
	struct mlx_accel_core_device *dev = context->sb_dev->accel_device;

	if (!dev)
		return -ENXIO;

	switch (cmd) {
	case IOCTL_ACCESS_TYPE:
		if (arg > MLX_ACCEL_ACCESS_TYPE_MAX) {
			pr_err("unknown access type %lu\n", arg);
			err = -EINVAL;
			break;
		}
		context->access_type = arg;
		break;
	case IOCTL_FPGA_LOAD:
		if (arg > MLX_ACCEL_IMAGE_MAX) {
			pr_err("unknown image type %lu\n", arg);
			err = -EINVAL;
			break;
		}
		err = mlx_accel_core_device_reload(dev, arg);
		break;
	case IOCTL_FPGA_RESET:
		err = mlx_accel_core_device_reload(dev,
						   MLX_ACCEL_IMAGE_MAX + 1);
		break;
	case IOCTL_FPGA_IMAGE_SEL:
		if (arg > MLX_ACCEL_IMAGE_MAX) {
			pr_err("unknown image type %lu\n", arg);
			err = -EINVAL;
			break;
		}
		err = mlx_accel_core_flash_select(dev, arg);
		break;
	case IOCTL_FPGA_QUERY:
		query.status = dev->state;
		query.admin_image = dev->last_admin_image;
		query.oper_image = dev->last_oper_image;
		if (err)
			break;

		if (copy_to_user((void __user *)arg, &query, sizeof(query))) {
			pr_err("Failed to copy data to user buffer\n");
			err = -EFAULT;
		}
		break;
	default:
		pr_err("unknown ioctl command 0x%08x\n", cmd);
		err = -ENOIOCTLCMD;
	}
	return err;
}

static const struct file_operations tools_fops = {
		.owner = THIS_MODULE,
		.open = tools_char_open,
		.release = tools_char_release,
		.read = tools_char_read,
		.write = tools_char_write,
		.llseek = tools_char_llseek,
		.unlocked_ioctl = tools_char_ioctl,
};

int mlx_accel_tools_char_add_one(struct mlx_accel_tools_dev *sb_dev)
{
	int ret = 0;

	ret = ida_simple_get(&minor_alloc, 1, 0, GFP_KERNEL);
	if (ret < 0) {
		dev_err(&sb_dev->accel_device->hw_dev->pdev->dev,
			"Failed to allocate minor number: %d", ret);
		goto out;
	}
	sb_dev->dev = MKDEV(major_number, ret);

	atomic_set(&sb_dev->open_count, 0);
	cdev_init(&sb_dev->cdev, &tools_fops);
	ret = cdev_add(&sb_dev->cdev, sb_dev->dev, 1);
	if (ret) {
		pr_err("Failed to add cdev: %d\n", ret);
		goto err_minor;
	}

	sb_dev->char_device = device_create(char_class, NULL, sb_dev->dev, NULL,
					    "%s%s",
					    sb_dev->accel_device->name,
					    MLX_ACCEL_TOOLS_NAME_SUFFIX);
	if (IS_ERR(sb_dev->char_device)) {
		ret = PTR_ERR(sb_dev->char_device);
		sb_dev->char_device = NULL;
		pr_err("Failed to create a char device: %d\n", ret);
		goto err_cdev;
	}

	pr_debug("mlx_accel_tools char device %u:%u created\n",
		 MAJOR(sb_dev->dev), MINOR(sb_dev->dev));
	goto out;

err_cdev:
	cdev_del(&sb_dev->cdev);
err_minor:
	ida_simple_remove(&minor_alloc, MINOR(sb_dev->dev));
out:
	return ret;
}

void mlx_accel_tools_char_remove_one(struct mlx_accel_tools_dev *sb_dev)
{
	WARN_ON(atomic_read(&sb_dev->open_count) > 0);
	device_destroy(char_class, sb_dev->dev);
	cdev_del(&sb_dev->cdev);
	ida_simple_remove(&minor_alloc, MINOR(sb_dev->dev));
	pr_debug("mlx_accel_tools char device %u:%u destroyed\n",
		 MAJOR(sb_dev->dev), MINOR(sb_dev->dev));
}

int mlx_accel_tools_char_init(void)
{
	int ret = 0;

	major_number = register_chrdev(0, MLX_ACCEL_TOOLS_DRIVER_NAME,
				       &tools_fops);
	if (major_number < 0) {
		ret = major_number;
		pr_err("Failed to register major number for char device: %d\n",
		       ret);
		goto out;
	}
	pr_debug("tools major number is %d\n", major_number);

	char_class = class_create(THIS_MODULE, MLX_ACCEL_TOOLS_DRIVER_NAME);
	if (IS_ERR(char_class)) {
		ret = PTR_ERR(char_class);
		pr_err("Failed to create char class: %d\n", ret);
		goto err_chrdev;
	}

	ida_init(&minor_alloc);

	goto out;

err_chrdev:
	unregister_chrdev(major_number, MLX_ACCEL_TOOLS_DRIVER_NAME);

out:
	return ret;
}

void mlx_accel_tools_char_deinit(void)
{
	ida_destroy(&minor_alloc);
	class_destroy(char_class);
	unregister_chrdev(major_number, MLX_ACCEL_TOOLS_DRIVER_NAME);
	pr_debug("tools major number freed\n");
}
