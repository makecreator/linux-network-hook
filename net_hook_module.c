#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif 

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/fs.h> 
#include <linux/semaphore.h> 
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include <net/tcp.h> 
#include <net/icmp.h>

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("makecreator<makecreator@gmail.com>");

#undef  MAX_DATA_LENGTH 
#define MAX_DATA_LENGTH 	1500

#undef  LOG_FILE  	
#define LOG_FILE 		"/sdcard/net_hook/net_hook_log" 

#undef  KEYWORD_FILE 		
#define KEYWORD_FILE		"/data/data/com.android.genius/files/keyword_table" 

/*
#undef  TIP_EXECUTE_FILE
#define TIP_EXECUTE_FILE 	"/home/NetFilterTip.jar"
*/

#undef  MAX_SEARCH_WORD_NUM
#define MAX_SEARCH_WORD_NUM 	5

#undef  REFERER_WORD
#define REFERER_WORD		"Referer: " 

#undef  GET_WORD
#define GET_WORD 		"GET "

#undef  MAX_KEY_WORD_LEN	
#define MAX_KEY_WORD_LEN 	200

#undef  MAX_KEY_WORD_TABLE_SIZE	
#define MAX_KEY_WORD_TABLE_SIZE	200

#undef  DISABLE_NET_TIME_S
#define DISABLE_NET_TIME_S	10

#undef  CLEAR_HISTORY_WORD	
#define CLEAR_HISTORY_WORD	20

#undef  INTERCEPTED_INFO_PREFIX
#define INTERCEPTED_INFO_PREFIX	"AndroidGeniusNetInterceptedInfo"

struct search_engine_key {
	char *search_engine_name; 
	char *search_word[MAX_SEARCH_WORD_NUM];
	int search_word_number; 
}; 

enum url_code {
	UTF_8, GB2312, UNKNOWN
}; 

struct keyword_structure {
	char source_word[MAX_KEY_WORD_LEN]; 
	char utf8_word[MAX_KEY_WORD_LEN]; 
	char gb2312_word[MAX_KEY_WORD_LEN]; 
	char utf8_url_word[MAX_KEY_WORD_LEN]; 
	char gb2312_url_word[MAX_KEY_WORD_LEN]; 
}; 

static struct nf_hook_ops nfho;
static char data_copy[MAX_DATA_LENGTH]; 
static int data_len; 
static int referer_word_len; 
static int get_word_len; 
static char url[MAX_DATA_LENGTH]; 
static char keyword[MAX_DATA_LENGTH]; 
static int fail[MAX_DATA_LENGTH];  //kmp_match 
static char *char_encode_name[] = {
	"utf-8", "gb2312" 
}; 
static enum url_code url_encode[] = { UTF_8, GB2312 }; 
static int char_encode_name_size = sizeof (char_encode_name) / sizeof (char *); 
// static enum url_code current_url_encode; 

static struct search_engine_key seks[] = {
	{ "114",       { "kw="                                 }, 1 }, 
	{ "115",       { "q="                                  }, 1 }, 
	{ "3721",      { "p="                                  }, 1 }, 
	{ "alltheweb", { "q="                                  }, 1 }, 
	{ "baidu",     { "kw=", "wd=", "word="                 }, 3 }, 
	{ "bing",      { "q="                                  }, 1 }, 
	{ "google",    { "q="                                  }, 1 }, 
	{ "lycos",     { "query="                              }, 1 }, 
	{ "onseek",    { "keyword="                            }, 1 }, 
	{ "openfind",  { "query="                              }, 1 }, 
	{ "msn",       { "q="                                  }, 1 }, 
	{ "qq",        { "word="                               }, 1 }, 
	{ "tom",       { "word="                               }, 1 }, 
	{ "sina",      { "query=", "word=", "searchkey=", "q=" }, 4 }, 
	{ "sogou",     { "query="                              }, 1 }, 
	{ "sohu",      { "key_word=", "query=", "word="        }, 3 }, 
	{ "soso",      { "w="                                  }, 1 }, 
	{ "yahoo",     { "p="                                  }, 1 }, 
	{ "yisou",     { "p="                                  }, 1 }, 
	{ "youdao",    { "q="                                  }, 1 }, 
	{ "zhongsou",  { "w="                                  }, 1 }
}; 

static const int keys_size = sizeof (seks) / sizeof (struct search_engine_key); 

static struct keyword_structure keyword_table[MAX_KEY_WORD_TABLE_SIZE]; 
static int keyword_table_size = 0; 

/* timer */
static struct timer_list stimer; 
static int has_set_timer = 0; 

static int intercept_all = 0; 

static char last_intercepted_keyword[MAX_KEY_WORD_LEN]; 

/* semaphore */
static struct semaphore sema; 
static struct semaphore log_file_write_sema; 

static struct task_struct *sync_task = NULL; 

static struct timex current_time; 

static int write_file(const char *filename, const char *wdata); 
void del_moudle_timer(void); 
static void send_reset(struct sk_buff *oldskb, int hook); 

void init_sem(void) 
{
	sema_init(&sema, 1); 
	sema_init(&log_file_write_sema, 1); 
}

void timer_handler(unsigned long data) 
{
	// intercept_all = 0; 
	// del_timer(&stimer); 
	if (strcmp(last_intercepted_keyword, "") != 0) { 
		// write_file(LOG_FILE, "");  
		strcpy(last_intercepted_keyword, ""); 
	}
	has_set_timer = 0; 
} 

void set_up_timer(void) 
{
	del_moudle_timer(); 
	init_timer(&stimer); 
	stimer.data = 0; 
	stimer.expires = jiffies + CLEAR_HISTORY_WORD * HZ; 
	stimer.function = timer_handler; 
	add_timer(&stimer); 
	// intercept_all = 1; 
	has_set_timer = 1; 
}

void del_moudle_timer(void) 
{
	if (has_set_timer == 1) { 
		has_set_timer = 0; 
		del_timer(&stimer); 
	} 
} 

void print_intercepted_info(const char *word) 
{
	do_gettimeofday(&(current_time.time)); 
	printk("%s %lu %s \n", INTERCEPTED_INFO_PREFIX, current_time.time.tv_sec, word); 
}

static int sync_log_file(void *arg) 
{
	write_file(LOG_FILE, last_intercepted_keyword); 
	return 0; 
}

void run_sync_log_thread(void) 
{
	int rc; 
	if (sync_task != NULL) {
		kthread_stop(sync_task); 
	} 
	sync_task = kthread_run(sync_log_file, NULL, "%s", "SYNC_LOG_THREAD"); 
	if (IS_ERR(sync_task)) {
		rc = PTR_ERR(sync_task); 
		printk("create sync_log_thread error: %d\n", rc); 
	} 
}

/*
void send_unreach_icmp(const int id, const char *src) 
{
	struct iphdr *ip_header; 
	struct icmphdr *icmp_header; 
	char *bufferl 
	unsigned short buffer_size; 
	
	buffer_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + sizeof (struct timeval); 
	buffer = (char *)kmalloc(buffer_size); 
	memset(buffer, 0, sizeof (buffer)); 
	
	ip_header = (struct iphdr *)buffer; 
	ip_header->ihl = 5; 
	ip_header->version = 4; 
	ip_header->tos = 0; 
	ip_header->tot_len = htons(buffer_size); 
	ip_header->id = id; 
	ip_header->ttl = 64; 
	ip_header->frag_off = 0x40; 
	ip_header->protocol = IPPROTO_ICMP; 
	ip_header->check = 0; 
	ip_header->daddr = inet_addr("127.0.0.1"); 
	ip_header->saddr = inet_addr(src); 
	
	icmp_header = (struct icmphdr *)(ip_header + 1); 
	icmp_header->type = 0; 
	icmp_header->code = 0; 
	icmp_header->un.echo.id = htons(src_port); 
	icmp_header->un.echo.sequence = 0;
	struct timeval *tp = (struct timeval *)&buffer[28];
}
*/

void modify_socket_to_unreach(struct sk_buff *skb) 
{
	struct iphdr *iph; 
	struct tcphdr *th; 
        int size; 
        int doff; 
        // skb->ip_summed = CHECKSUM_NONE; 
	iph = ip_hdr(skb); 
	th = (struct tcphdr *)((__u32 *)iph + iph->ihl); 
	
	iph->ttl = 1; 
	iph->check = 0;
	// iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl); 
	size = ntohs(iph->tot_len) - (iph->ihl * 4);
	doff = th->doff << 2; 
	skb->csum = 0; 
	// skb->csum =  skb_checksum (skb, doff, skb->len - doff, 0);  
	// ip_send_check(iph); 
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
} 

int kmp_match(const char *str, int ls, const char *pat, int lp) 
{
	int i, j; 
	
	i = 0; 
	memset(fail, -1, sizeof (char) * (lp + 1)); 
	
	for (j = 1; j < lp; j++) {
		for (i = fail[j - 1]; i >= 0 && pat[i + 1] != pat[j]; i = fail[i]); 
		fail[j] = (pat[i + 1] == pat[j] ? i + 1 : -1); 
	} 
	for (i = j = 0; i < ls && j < lp; i++) {
		if (str[i] == pat[j]) 
			j++; 
		else if (j) 
			j = fail[j - 1] + 1, i--; 
	} 
	return j == lp ? (i - lp) : ls; 
} 

int search_first_word(const char *src, const char *word) 
{
	// int i; 
	int src_len = strlen(src); 
	int word_len = strlen(word); 
	
	if (word_len > src_len) 
		return src_len; 
	if (word_len == src_len) {
		if (strcmp(src, word) == 0) {
			return 0; 
		} 
		return src_len; 
	} 
	/*
	for (i = 0; i < src_len - word_len; i++) {
		if (strncmp(src + i, word, word_len) == 0) {
			return i; 
		} 
	} 
	return src_len; 
	*/ 
	return kmp_match(src, src_len, word, word_len); 
}

enum url_code get_url_code(const char *src_url) 
{
	int i; 
	int pos; 
	int src_url_len = strlen(src_url); 
	
	for (i = 0; i < char_encode_name_size; i++) {
		pos = search_first_word(src_url, char_encode_name[i]); 
		if (pos < src_url_len) {
			return url_encode[i]; 
		} 
	} 
	return UNKNOWN; 
}

void get_search_url_link(const char *src_data, char *url_data) 
{
	int i, j; 
	int pos, url_first_pos; 
	int src_data_len = strlen(src_data); 
	
	pos = search_first_word(src_data, GET_WORD); 
	
	if (pos < src_data_len) {
		url_first_pos = pos + get_word_len; 
	} else {
		pos = search_first_word(src_data, REFERER_WORD); 
	
		if (pos < src_data_len) {
			url_first_pos = pos + referer_word_len; 
		} else {
			strcpy(url_data, ""); 
			return; 
		}  
	} 
	
	i = 0; 
	j = url_first_pos; 
	while (j < src_data_len && src_data[j] != ' ' && 
		src_data[j] != '\n' && src_data[j] != '\t') {
		url_data[i] = src_data[j]; 
		i++; 
		j++; 
	} 
	url_data[i] = '\0';
}

void get_search_key_word(const char *src_url, char *exact_key_word) 
{
	int i, j; 
	int pos, engine_name_end_pos, search_key_word_start_pos; 
	int src_url_len = strlen(src_url); 
	
	for (i = 0; i < keys_size; i++) {
		pos = search_first_word(src_url, seks[i].search_engine_name); 
		if (pos < src_url_len) {
			break; 
		} 
	} 
	
	if (i == keys_size) {
		strcpy(exact_key_word, src_url); 
		return; 
	} 
	
	engine_name_end_pos = pos + strlen(seks[i].search_engine_name); 
	for (j = 0; j < seks[i].search_word_number; j++) {
		pos = search_first_word(src_url, seks[i].search_word[j]); 
		if (pos < src_url_len) {
			break; 
		} 
	} 
	
	if (j == seks[i].search_word_number) {
		strcpy(exact_key_word, src_url); 
		return; 
	} 
	
	pos += strlen(seks[i].search_word[j]); 
	search_key_word_start_pos = pos; 
	
	i = 0; 
	j = search_key_word_start_pos; 
	while (j < src_url_len && src_url[j] != '&' && 
		src_url[j] != ' ' && src_url[j] != '\n' && 
		src_url[j] != '\t') {
		exact_key_word[i] = src_url[j]; 
		i++; 
		j++; 
	} 
	exact_key_word[i] = '\0'; 
}

// create the log file to record the some information
void create_log_file(const char *filename) 
{
	struct file *filp = NULL; 
	
	filp = filp_open(filename, O_CREAT, 0777); 
	
	if (IS_ERR(filp)) {
		printk("%s create fail!\n", filename); 
		return; 
	} 
	
	filp_close(filp, current->files); 
	
}

void get_keyword_table(void) 
{
	mm_segment_t fs; 
	struct file *filp = NULL; 
	loff_t *file_offset = 0; 
	char *buff; 
	int bsize = 256; 
	int cur_buf_pos; 
	int buf_real_len; 
	int i, j; 
	int prefix_word_len; 
	
	fs = get_fs(); 
	set_fs(get_ds()); 
	
	filp = filp_open(KEYWORD_FILE, O_RDONLY, 0); 
	if (IS_ERR(filp)) {
		printk(KERN_ERR "%s filp_open error: "
			"unable to open file!\n", KEYWORD_FILE); 
		return; 
	} 
	
	buff = (char *)kmalloc(bsize + 100, GFP_KERNEL); 
	
	keyword_table_size = 0; 
	file_offset = &(filp->f_pos); 
	j = 0; 
	while ((buf_real_len = vfs_read(filp, buff, bsize, file_offset)) > 0) { 
		buff[buf_real_len] = 0; 
		// printk("%s\n end\n", buff); 
		
		cur_buf_pos = 0; 
		while (cur_buf_pos < buf_real_len) {
			for (i = cur_buf_pos; i < buf_real_len; i++, j++) {
				if (buff[i] == '\n') 
					break; 
				data_copy[j] = buff[i]; 
			} 
			cur_buf_pos = i + 1; 
			if (buff[i] == '\n' || buf_real_len < bsize)  { // data_copy is one line
				data_copy[j] = '\0'; 
				j = 0; 
			} else {
				continue; 
			} 
			
			// exact data from data_copy ..
			if (data_copy[0] == '#') {
				i = 1; 
				while (data_copy[i] == ' ') 
					i++; 
				strcpy(keyword_table[keyword_table_size].source_word, 
					data_copy + i); 
			} else if (strncmp(data_copy, "UTF-8:  ", 
					(prefix_word_len = strlen("UTF-8:  "))) == 0) {
				strcpy(keyword_table[keyword_table_size].utf8_word, 
					data_copy + prefix_word_len); 
			} else if (strncmp(data_copy, "GB2312: ", 
					(prefix_word_len = strlen("GB2312: "))) == 0) { 
				strcpy(keyword_table[keyword_table_size].gb2312_word, 
					data_copy + prefix_word_len); 
			} else if (strncmp(data_copy, "UTF-8URL: ", 
					(prefix_word_len = strlen("UTF-8URL: "))) == 0) {
				strcpy(keyword_table[keyword_table_size].utf8_url_word, 
					data_copy + prefix_word_len); 
			} else if (strncmp(data_copy, "GB2312URL: ", 
					(prefix_word_len = strlen("GB2312URL: "))) == 0) {
				strcpy(keyword_table[keyword_table_size].gb2312_url_word, 
					data_copy + prefix_word_len); 
				++keyword_table_size; 
			} 
		} 
	} 
	kfree(buff); 
	filp_close(filp, current->files); 
	set_fs(fs); 
}

// use this function to write some data to given file 
static int write_file(const char *filename, const char *wdata) 
{
	mm_segment_t fs; 
	struct file *filp = NULL; 
	struct inode *node = NULL; 
	loff_t nef_size = 0; 
	loff_t tmp_file_offset; 
	ssize_t nwritten; 
	int rc = -EINVAL; 
	int str_len; 
	
	// down(&log_file_write_sema); 

	fs = get_fs(); 
	set_fs(KERNEL_DS); 
	
	filp = filp_open(filename, O_RDWR, 0); 
	if (IS_ERR(filp)) {
		printk(KERN_ERR "%s filp_open error: "
			"unable to open file!\n", filename); 
		up(&log_file_write_sema); 
		return PTR_ERR(filp); 
	} 
	
	if (filp->f_path.dentry) { 
		node = filp->f_path.dentry->d_inode; 
	} else {
		printk(KERN_ERR "Invalid " 
			"filp->f_path.dentry value!\n"); 
		goto out; 
	} 
	
	nef_size = i_size_read(node->i_mapping->host); 
	if (nef_size < 0) {
		printk(KERN_ERR "Invalid "
			"file size: 0x%11x\n", (int)nef_size); 
		goto out; 
	} else if (nef_size > 0) {
		printk("file is not empty\n"); 
		goto out; 
	} 
	
	if (strcmp(wdata, "") == 0) {
		goto out; 
	} 

	str_len = strlen(wdata) + 1; 
	tmp_file_offset = nef_size; 
	nwritten = vfs_write(filp, (const char __user *)wdata, 
				MAX_DATA_LENGTH, &tmp_file_offset); 
	/*
	if (nwritten < str_len) {
		printk(KERN_ERR "%s, line %d - "
			"file partial write: " 
			"%d bytes\n", __FILE__, __LINE__, (int)nwritten); 
		goto out; 
	} */
	
	rc = 0; 
	out: 
		filp_close(filp, current->files); 
		set_fs(fs); 
		up(&log_file_write_sema); 

		return rc; 
} 

/*
// use this function to write some data to given file 
static int write_file(const char *filename, const char *wdata) 
{
	mm_segment_t fs; 
	struct file *filp = NULL; 
	ssize_t nwritten; 
	
	down(&log_file_write_sema); 
	
	fs = get_fs(); 
	set_fs(get_ds()); 

	filp = filp_open(filename, O_RDWR, 0600); 
	if (filp == NULL) {
		printk(KERN_ERR "%s filp_open error: "
			"unable to open file!\n", filename); 
		up(&log_file_write_sema); 
		return 0;  
	} 

	nwritten = filp->f_op->write(filp, wdata, 
				MAX_DATA_LENGTH, &filp->f_pos); 

	filp_close(filp, NULL); 
	set_fs(fs); 
	up(&log_file_write_sema); 

	return nwritten; 
} 
*/

int is_match_keyword(const char *given_keyword) 
{
	int i; 
	int given_keyword_len = strlen(given_keyword); 
	
	for (i = 0; i < keyword_table_size; i++) {
		if (search_first_word(given_keyword, 
			keyword_table[i].source_word) < given_keyword_len) 
			goto matched; 
		if (search_first_word(given_keyword, 
			keyword_table[i].utf8_word) < given_keyword_len) 
			goto matched; 
		if (search_first_word(given_keyword, 
			keyword_table[i].gb2312_word) < given_keyword_len) 
			goto matched; 
		if (search_first_word(given_keyword, 
			keyword_table[i].utf8_url_word) < given_keyword_len) 
			goto matched; 
		if (search_first_word(given_keyword, 
			keyword_table[i].gb2312_url_word) < given_keyword_len) 
			goto matched; 
	} 
	
	return 0; 
	
	matched: 
		// printk("NOT ALLOW TO SEARCH %s\n", keyword_table[i].source_word); 
		print_intercepted_info(keyword_table[i].source_word); 
		/*
		if (has_set_timer == 0) {
			strcpy(last_intercepted_keyword, keyword_table[i].source_word); 
			strcat(last_intercepted_keyword, "\n"); 
			// write_file(LOG_FILE, last_intercepted_keyword); 
			// run_sync_log_thread(); 
			// set_up_timer(); 
		} */
		return 1; 
} 

// to fill the end character in the tcp data 
void fill_zero_bytes(void) 
{
	int i; 
	for (i = 0; i < data_len; i++) {
		if (data_copy[i] == 0) {
			data_copy[i] = ' '; 
		} 
	} 
} 

// the hook function 
unsigned int hook_func(unsigned int hooknum, 
			struct sk_buff *skb, 
			const struct net_device *in, 
			const struct net_device *out, 
			int (*okfn)(struct sk_buff *)) 
{
	/*
	char data[MAX_DATA_LENGTH]; 
	struct sk_buff *tmp_skb = skb_copy(skb, GFP_ATOMIC);
	
	strcpy(data, tmp_skb->data); 
	printk(tmp_skb->data); 
	*/ 
	char *data; 
	struct iphdr *iph; 
	struct tcphdr *th; 
	// struct udphdr *uh; 
	/*
	if (intercept_all) {
		return NF_DROP; 
	} */
	if (!skb) 
		return NF_ACCEPT; 
		
	if (0 != skb_linearize(skb)) { 
		printk("linearize failed!"); 
		return NF_ACCEPT;
        }
        
	iph = ip_hdr(skb); 
	if (!iph) 
		return NF_ACCEPT; 
	// printk("proticol is %d\n", iph->protocol); 
	/*
	if (iph->protocol == IPPROTO_UDP) { 
		uh = (struct udphdr *)((__u32 *)iph + iph->ihl); // udp head
		// uh = (struct udphdr *)(skb->data + iph->ihl * 4); 
		data = (char *)((__u32 *)uh + sizeof(*uh)); // begin address of data 
		// data = skb->data + 8; 
		return NF_ACCEPT; 
	} else */ 
	if (iph->protocol == IPPROTO_TCP) {
		th = (struct tcphdr *)((__u32 *)iph + iph->ihl); // tcp head
		// th = (struct tcphdr *)(skb->data + (iph->ihl * 4)); 
		data = (char *)((__u32 *)th + th->doff); // begin address of data 
	} else {
		// printk("socket isn't tcp packet!\n"); 
		// strcpy(last_intercepted_keyword, ""); 
		print_intercepted_info(""); 
		return NF_ACCEPT; 
	} 
	data_len = (char *)skb->tail - data; 
	if (data_len == 0) 
		return NF_ACCEPT;
		
	// printk("data_len: %d\t", data_len); 
	
	// down(&sema); 
	/*
	if (intercept_all) {
		// up(&sema);
		return NF_DROP; 
	} */
	memcpy(data_copy, data, data_len); 
	data_copy[data_len] = '\0'; 
	fill_zero_bytes(); 
	
	/*
	if (match_word(word)) { 
		printk("MATCH!!!!!!!!!!!!!!!!! DROP!!!!!!!!!\n"); 
		return NF_DROP; 
	} */
	// write_file(LOG_FILE, data_copy); 
	// write_file(LOG_FILE, "\n"); 
	
	get_search_url_link(data_copy, url); 
	get_search_key_word(url, keyword); 
	
	// printk("net_data: %s\n", data_copy); 
	// printk("url: %s\n", url); 
	// printk("key_word: %s\n", keyword); 
	
	if (is_match_keyword(keyword)) { 
		// printk("match!! drop!!\n"); 
		// set_up_timer(); 
		// up(&sema);  
		send_reset(skb, hooknum); 

		return NF_DROP; 
		// modify_socket_to_unreach(skb); 
	} 
	
	// up(&sema); 
	print_intercepted_info(""); 
	return NF_ACCEPT; 
} 

void show_keyword_table(void) 
{
	int i; 
	
	for (i = 0; i < keyword_table_size; i++) {
		printk("%s\n", keyword_table[i].source_word); 
		printk("%s\n", keyword_table[i].utf8_word);
		printk("%s\n", keyword_table[i].gb2312_word);
		printk("%s\n", keyword_table[i].utf8_url_word); 
		printk("%s\n", keyword_table[i].gb2312_url_word); 
	} 
} 

void register_hook(void) 
{
	nfho.hook = hook_func; 
	// nfho.hooknum = NF_INET_PRE_ROUTING; 
	// nfho.hooknum =  NF_INET_LOCAL_OUT; 
	nfho.hooknum =  NF_INET_POST_ROUTING; 
	nfho.pf = PF_INET; 
	nfho.priority = NF_IP_PRI_FIRST; 
	nf_register_hook(&nfho); 
} 

void init_env(void) 
{
	// create_log_file(LOG_FILE); 
	referer_word_len = strlen(REFERER_WORD); 
	get_word_len = strlen(GET_WORD); 
	init_sem(); 
	intercept_all = 0; 
	get_keyword_table(); 
	show_keyword_table(); 
	strcpy(last_intercepted_keyword, ""); 
	set_up_timer(); 
} 

// initialize the module 
int init_module() 
{
	register_hook(); 
	init_env(); 
	
	return 0; 
} 

void cleanup_module() 
{
	// timer_handler(stimer.data); 
	// del_moudle_timer(); 
	nf_unregister_hook(&nfho); 
} 

/* use the source of linux-2.6.36.1/net/ipv4/netfilter/ipt_REJECT.c */
/* Send RST reply */
static void send_reset(struct sk_buff *oldskb, int hook)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	struct tcphdr _otcph, *tcph;
	unsigned int addr_type;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
		return;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
				 sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return;

	/* No RST for RST. */
	if (oth->rst)
		return;

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return;
	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= sizeof(struct iphdr) / 4;
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= IPPROTO_TCP;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;

	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= sizeof(struct tcphdr) / 4;

	if (oth->ack)
		tcph->seq = oth->ack_seq;
	else {
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}

	tcph->rst	= 1;
	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
				    niph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	addr_type = RTN_UNSPEC;
	if (hook != NF_INET_FORWARD
#ifdef CONFIG_BRIDGE_NETFILTER
	    || (nskb->nf_bridge && nskb->nf_bridge->mask & BRNF_BRIDGED)
#endif
	   )
		addr_type = RTN_LOCAL;

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(nskb, addr_type))
		goto free_nskb;

	niph->ttl	= dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	ip_local_out(nskb);
	return;

 free_nskb:
	kfree_skb(nskb);
}

