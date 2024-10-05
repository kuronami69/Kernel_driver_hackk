#include "process.h"
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/version.h>

#define ARC_PATH_MAX 256

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);
#endif

uintptr_t get_module_base(pid_t pid, char *name)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	struct vma_iterator vmi;
#endif

	// 获取 pid 结构
	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return 0;  // 错误处理，返回 0 表示失败
	}

	// 获取 task_struct
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return 0;  // 错误处理
	}

	// 获取 mm_struct
	mm = get_task_mm(task);
	if (!mm)
	{
		return 0;  // 错误处理
	}

	// 在使用完 mm 之后再释放
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma)
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
	{
		char buf[ARC_PATH_MAX];
		char *path_nm = "";

		if (vma->vm_file)
		{
			// 获取文件路径
			path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
			// 检查路径是否有效
			if (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name))
			{
				mmput(mm);  // 在找到模块基地址后释放 mm
				return vma->vm_start;  // 返回模块基地址
			}
		}
	}

	mmput(mm);  // 没有找到模块时也需要释放 mm
	return 0;   // 返回 0 表示没有找到
}
