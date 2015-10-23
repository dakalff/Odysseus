/*
 *  sshtool
 *
 *  Copyright (c) 2015 xerub
 *  Copyright (c) 1998 Pavel Machek
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define enable_interrupt_key()
#define disable_interrupt_key()
#define got_interrupt() 0

static int sockr, sockw;

size_t
g_strlcpy(char *dest, const char *src, size_t dest_size)
{
  register char *d = dest;
  register const char *s = src;
  register size_t n = dest_size;
  
  if (dest == NULL || src == NULL) return 0;
  
  /* Copy as many bytes as will fit */
  if (n != 0 && --n != 0)
    do
      {
	register char c = *s++;
	
	*d++ = c;
	if (c == 0)
	  break;
      }
    while (--n != 0);
  
  /* If not enough room in dest, add NUL and traverse rest of src */
  if (n == 0)
    {
      if (dest_size != 0)
	*d = 0;
      while (*s++)
	;
    }
  
  return s - src - 1;  /* count does not include NUL */
}

void __attribute__((noreturn))
vfs_die(const char *message)
{
    fprintf(stderr, "%s", message);
    exit(1);
}

int
vfs_s_get_line (int sock, char *buf, int buf_len, char term)
{
    int i;
    char c;

    for (i = 0; i < buf_len - 1; i++, buf++){
	if (read (sock, buf, sizeof(char)) <= 0)
	    return 0;
	if (*buf == term){
	    *buf = 0;
	    return 1;
	}
    }

    /* Line is too long - terminate buffer and discard the rest of line */
    *buf = 0;
    while (read (sock, &c, sizeof (c)) > 0) {
	if (c == '\n')
	    return 1;
    }
    return 0;
}

int
vfs_s_get_line_interruptible (char *buffer, int size, int fd)
{
    int n;
    int i;

    enable_interrupt_key ();
    for (i = 0; i < size-1; i++){
	n = read (fd, buffer+i, 1);
	disable_interrupt_key ();
	if (n == -1 && errno == EINTR){
	    buffer [i] = 0;
	    return EINTR;
	}
	if (n == 0){
	    buffer [i] = 0;
	    return 0;
	}
	if (buffer [i] == '\n'){
	    buffer [i] = 0;
	    return 1;
	}
    }
    buffer [size-1] = 0;
    return 0;
}

/*
 * Reply codes.
 */
#define PRELIM		1	/* positive preliminary */
#define COMPLETE	2	/* positive completion */
#define CONTINUE	3	/* positive intermediate */
#define TRANSIENT	4	/* transient negative completion */
#define ERROR		5	/* permanent negative completion */

/* command wait_flag: */
#define NONE        0x00
#define WAIT_REPLY  0x01
#define WANT_STRING 0x02
static char reply_str [80];

static int fish_decode_reply (char *s, int was_garbage)
{
    int code;
    if (!sscanf(s, "%d", &code)) {
	code = 500;
	return 5;
    }
    if (code<100) return was_garbage ? ERROR : (!code ? COMPLETE : PRELIM);
    return code / 100;
}

/* Returns a reply code, check /usr/include/arpa/ftp.h for possible values */
static int fish_get_reply (int sock, char *string_buf, int string_len)
{
    char answer[1024];
    int was_garbage = 0;
    
    for (;;) {
        if (!vfs_s_get_line(sock, answer, sizeof(answer), '\n')) {
	    if (string_buf)
		*string_buf = 0;
	    return 4;
	}

	if (strncmp(answer, "### ", 4)) {
	    was_garbage = 1;
	    if (string_buf)
		g_strlcpy(string_buf, answer, string_len);
	} else return fish_decode_reply(answer+4, was_garbage);
    }
}

static int
fish_command (
	      int wait_reply, const char *fmt, ...)
{
    va_list ap;
    char *str;
    int status;

    va_start (ap, fmt);

    status = vasprintf(&str, fmt, ap);
    va_end (ap);

    if (status < 0)
	return TRANSIENT;

    enable_interrupt_key ();

    status = write (sockw, str, strlen (str));
    free (str);

    disable_interrupt_key ();
    if (status < 0)
	return TRANSIENT;

    if (wait_reply)
	return fish_get_reply (sockr,
			       (wait_reply & WANT_STRING) ? reply_str :
			       NULL, sizeof (reply_str) - 1);
    return COMPLETE;
}

static void
fish_pipeopen(const char *argv[])
{
    int fileset1[2], fileset2[2];
    int res;

    if ((pipe(fileset1)<0) || (pipe(fileset2)<0)) 
	vfs_die("Cannot pipe(): %m.");
    
    if ((res = fork())) {
        if (res<0) vfs_die("Cannot fork(): %m.");
	/* We are the parent */
	close(fileset1[0]);
	sockw = fileset1[1];
	close(fileset2[1]);
	sockr = fileset2[0];
    } else {
        close(0);
	dup(fileset1[0]);
	close(fileset1[0]); close(fileset1[1]);
	close(1);
	dup(fileset2[1]);
	close(fileset2[0]); close(fileset2[1]);
	execvp(*argv, (char **)argv);
	_exit(3);
    }
}

#define ERRNOR(ecode, code) do { fprintf(stderr, #ecode "\n"); return code; } while (0)

static char *
fish_retra(const char *remote_path, unsigned *sz)
{
    int rv;
    char *ptr, *buf;
    unsigned total = 0, got = 0;
    const char *temporary_path = "tmp/retra.tar";
    const char *quoted_path = remote_path;

    *sz = 0;

    /* Set up remote locale to C, otherwise dates cannot be recognized */
    if (fish_command(WAIT_REPLY, "LANG=C; LC_ALL=C; LC_TIME=C\nexport LANG; export LC_ALL; export LC_TIME\necho '### 200'\n") != COMPLETE)
	ERRNOR (E_PROTO, NULL);

    rv = fish_command(WANT_STRING,
		"#RETRA /%s\n"
	"if ls /%s >/dev/null 2>&1; then\n"
		"if tar -cf /%s /%s 2>/dev/null; then\n"
		"ls -ln /%s 2>/dev/null | (\n"
		  "read p l u g s r\n"
		  "echo \"$s\"\n"
		")\n"
		"echo '### 100'\n"
		"cat /%s\n"
		"rm /%s >/dev/null 2>&1\n"
		"echo '### 200'\n"
		"else\n"
		"echo '### 500'\n"
		"fi\n"
	"else\n"
		"echo 0\n"
		"echo '### 100'\n"
		"echo '### 200'\n"
	"fi\n",
		remote_path, quoted_path, temporary_path, quoted_path, temporary_path, temporary_path, temporary_path);
    if (rv != PRELIM)
	ERRNOR (E_REMOTE, NULL);
    if (sscanf( reply_str, "%u", &total )!=1)
	ERRNOR (E_REMOTE, NULL);

    ptr = buf = malloc(total);
    if (buf) {
	for (;;) {
	    int n = 0;
	    int len = total - got;
	    disable_interrupt_key();
	    while (len && ((n = read (sockr, ptr, len))<0)) {
		if ((errno == EINTR) && !got_interrupt())
		    continue;
		break;
	    }
	    enable_interrupt_key();

	    if (n>0) got += n;
	    if (n<0) vfs_die("ABORT\n");
	    if ((!n) && ((fish_get_reply (sockr, NULL, 0) != COMPLETE)))
		ERRNOR (E_REMOTE, NULL);

	    if (!n) break;
	    ptr += n;
	}
	*sz = total;
    }
    return buf;
}

static int
fish_stor(const char *remote_path, char *buf, unsigned sz)
{
    int rv;
    unsigned total;
    const char *quoted_name = remote_path;

    printf("fish: store %s: sending command...\n", remote_path);

    rv = fish_command (WAIT_REPLY,
	 "#STOR %lu /%s\n"
	 "echo '### 001'\n"
	 "file=/%s\n"
         "res=`exec 3>&1\n"
	 "(\n"
	   "head -c %lu -q - || echo DD >&3\n"
	 ") 2>/dev/null | (\n"
	   "cat > \"$file\"\n"
	   "cat > /dev/null\n"
	 ")`; [ \"$res\" = DD ] && {\n"
		"> \"$file\"\n"
		"rest=%lu\n"
		"while [ $rest -gt 0 ]\n"
		"do\n"
		"    cnt=`expr \\( $rest + 255 \\) / 256`\n"
		"    n=`dd bs=256 count=$cnt | tee -a \"$file\" | wc -c`\n"
		"    rest=`expr $rest - $n`\n"
		"done\n"
	 "}; echo '### 200'\n",
	 (unsigned long)sz, remote_path,
	 quoted_name, (unsigned long)sz,
	 (unsigned long)sz);
    if (rv != PRELIM) {
        ERRNOR(E_REMOTE, -1);
    }

    total = 0;
    
    while (1) {
	int t, n = 8192;
	if (total + n > sz) n = sz - total;
	if (n == 0)
	    break;
    	if ((t = write (sockw, buf, n)) != n) {
	    goto error_return;
	}
	disable_interrupt_key();
	total += n;
	buf += n;
	printf("fish: storing file %d (%lu)\n", total, (unsigned long) sz);
    }

    if (fish_get_reply (sockr, NULL, 0) != COMPLETE)
        ERRNOR (E_REMOTE, -1);
    return 0;
error_return:
    fish_get_reply(sockr, NULL, 0);
    return -1;
}

static int
fish_chmod (const char *path, int mode)
{
    int r;
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "#CHMOD %4.4o /%s\n"
				 "chmod %4.4o \"/%s\" 2>/dev/null\n"
				 "echo '### 000'\n", 
	    mode & 07777, path,
	    mode & 07777, path);

    r = fish_command (WAIT_REPLY, "%s", cmd);
    if (r != COMPLETE) ERRNOR (E_REMOTE, -1);
    return 0;
}

static int
fish_exec2 (const char *path, const char *arg)
{
    int res;
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "#EXEC2 /%s %s\n"
				 "/%s %s 2>/dev/null\n"
				 "echo '### 000'\n", 
	    path, arg, path, arg);

    res = fish_command (NONE, "%s", cmd);
    if (res != COMPLETE)
        ERRNOR (E_REMOTE, -1);

    while (1) {
	res = vfs_s_get_line_interruptible (cmd, sizeof (cmd), sockr); 
	if (!res || res == EINTR)
	    ERRNOR(E_CONNRESET, -1);
	if (!strncmp(cmd, "### ", 4))
	    break;
	printf("%s\n", cmd);
    }

    if (fish_decode_reply(cmd+4, 0) != COMPLETE)
        ERRNOR (E_REMOTE, -1);

    return 0;
}

static char *
read_file(const char *path, unsigned *size)
{
    FILE *f;
    size_t rv;
    size_t sz;
    void *buf;
    f = fopen(path, "rb");
    if (!f) {
	return NULL;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(sz);
    if (!buf) {
	fclose(f);
	return NULL;
    }
    rv = fread(buf, 1, sz, f);
    fclose(f);
    if (sz - rv) {
	free(buf);
	return NULL;
    }
    *size = sz;
    return buf;
}

int
main(int argc, char **argv)
{
    int status;
    char *savepath = NULL;
    char *kloader = NULL;
    char *ibsspath = NULL;

    const char *args[] = {
        "ssh",
        "-p", "2222",
        "-l", "root",
        "localhost",
        "echo FISH:; /bin/sh",
        NULL
    };
    char answer[2048];

    int opt;
    while ((opt = getopt(argc, argv, "hb:k:s:p:")) != -1) {
        switch (opt) {
            case 'p':
                args[2] = optarg;
                break;
            case 's':
                savepath = optarg;
                break;
            case 'k':
                kloader = optarg;
                break;
            case 'b':
                ibsspath = optarg;
                break;
            case 'h':
            default:
                fprintf(stderr, "usage: %s [-s baseband.tar] [-k kloader -b ibss] [-p PORT] [host]\n", argv[0]);
                return 1;
        }
    }
    if (optind < argc) {
        args[5] = argv[optind];
    }

    printf("fish: Connecting to %s:%s\n", args[5], args[2]);

    fish_pipeopen(args);

    printf("fish: Waiting for initial line...\n");
    if (!vfs_s_get_line(sockr, answer, sizeof (answer), ':'))
        ERRNOR(E_PROTO, -1);

    printf("fish: Sending initial line...\n");

    if (fish_command(WAIT_REPLY, "#FISH\necho; start_fish_server 2>&1; echo '### 200'\n") != COMPLETE)
        ERRNOR (E_PROTO, -1);

    printf("fish: Handshaking version...\n");
    if (fish_command(WAIT_REPLY, "#VER 0.0.0\necho '### 000'\n") != COMPLETE)
        ERRNOR (E_PROTO, -1);

    /* ... */
    if (savepath) {
        char *buf;
        unsigned sz;
        printf("fish: Starting linear transfer...\n");
        buf = fish_retra("usr/local/standalone/*", &sz);
        if (sz == 0) {
            free(buf);
            buf = fish_retra("usr/standalone/*", &sz);
        }
        if (buf) {
            FILE *f = fopen(savepath, "wb");
            if (f) {
                fwrite(buf, 1, sz, f);
                fclose(f);
            } else {
                printf("error: cannot write %s\n", savepath);
            }
            free(buf);
        }
        printf("fish: Transferred %u bytes\n", sz);
    } else if (kloader && ibsspath) {
        int rv = -1;
        unsigned sz1, sz2;
        char *buf1 = read_file(kloader, &sz1);
        char *buf2 = read_file(ibsspath, &sz2);
        if (buf1 && buf2) {
            rv = fish_stor("tmp/kloader", buf1, sz1);
            if (rv == 0) {
                rv = fish_chmod("tmp/kloader", 0755);
                if (rv == 0) {
                    rv = fish_stor("tmp/pwnediBSS", buf2, sz2);
                }
            }
        }
        free(buf2);
        free(buf1);
        if (rv == 0) {
            fish_exec2("tmp/kloader", "/tmp/pwnediBSS");
        } else {
            printf("error: cannot send %s and %s\n", kloader, ibsspath);
        }
    }
    /* ... */

    printf("fish: Disconnecting from %s\n", args[5]);

    fish_command(NONE, "#BYE\nexit\n");

    close(sockw);
    close(sockr);

    wait(&status);

    return 0;
}