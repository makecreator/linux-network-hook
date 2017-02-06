#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xb8bf2c60, "module_layout" },
	{ 0x7d11c268, "jiffies" },
	{ 0x53454054, "add_timer" },
	{ 0x1bc6285d, "init_timer_key" },
	{ 0xdd457564, "del_timer" },
	{ 0x9e4babac, "kfree_skb" },
	{ 0xe35c1de5, "ip_local_out" },
	{ 0xa2f0066c, "nf_ct_attach" },
	{ 0xe97bb509, "ip_route_me_harder" },
	{ 0xfa2a45e, "__memzero" },
	{ 0xf62645c0, "skb_put" },
	{ 0xd847c448, "__alloc_skb" },
	{ 0x17732511, "nf_ip_checksum" },
	{ 0x1c60952f, "skb_copy_bits" },
	{ 0x9d669763, "memcpy" },
	{ 0xacbc32c1, "__pskb_pull_tail" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x7a728ef4, "up" },
	{ 0x5dcb14ca, "vfs_write" },
	{ 0x14175bac, "wake_up_process" },
	{ 0x1f2f2903, "kthread_create" },
	{ 0xff993429, "kthread_stop" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x97255bdf, "strlen" },
	{ 0x4aabc7c4, "__tracepoint_kmalloc" },
	{ 0xe403478b, "malloc_sizes" },
	{ 0x37a0cba, "kfree" },
	{ 0xbf426e03, "vfs_read" },
	{ 0x84b183ae, "strncmp" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0xab3309be, "slab_buffer_size" },
	{ 0x85f2647b, "kmem_cache_alloc_notrace" },
	{ 0xe5352f5e, "filp_close" },
	{ 0x5bf8e30a, "filp_open" },
	{ 0xea147363, "printk" },
	{ 0x5c09d629, "nf_register_hook" },
	{ 0xe914e41e, "strcpy" },
	{ 0x66f9286d, "nf_unregister_hook" },
	{ 0xefd6cf06, "__aeabi_unwind_cpp_pr0" },
	{ 0x5f754e5a, "memset" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "2A113A9047AF659DC54FF51");
