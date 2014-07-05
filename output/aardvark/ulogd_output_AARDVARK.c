/* ulogd_AARDVARK.c, Version $Revision$
 *
 * ulogd output target for writing aardvark-style files (like tcpdump)
 *
 * (C) 2002-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

/* This is a timeval as stored on disk in a dumpfile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'
 */

struct aardvark_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

/*
 * How a `aardvark_pkthdr' is actually stored in the dumpfile.
 *
 * Do not change the format of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure),
 * and do not make the time stamp anything other than seconds and
 * microseconds (e.g., seconds and nanoseconds).  Instead:
 *
 *	introduce a new structure for the new format;
 *
 *	send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *	magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed record
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old record header as well as files with the new record header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libaardvark and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */

struct aardvark_sf_pkthdr {
	struct aardvark_timeval ts;		/* time stamp */
	uint32_t caplen;		/* length of portion present */
	uint32_t len;			/* length this packet (off wire) */
};

#ifndef ULOGD_AARDVARK_DEFAULT
#define ULOGD_AARDVARK_DEFAULT	"/var/log/ulogd.aardvark"
#endif

#ifndef ULOGD_AARDVARK_SYNC_DEFAULT
#define ULOGD_AARDVARK_SYNC_DEFAULT	0
#endif

#ifndef ULOGD_AARDVARK_DEFAULT_SERVER_IP
#define ULOGD_AARDVARK_DEFAULT_SERVER_IP "127.0.0.1"
#endif

#ifndef ULOGD_AARDVARK_BUF_DEFAULT
#define ULOGD_AARDVARK_BUF_DEFAULT	1024
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static struct config_keyset aardvark_kset = {
	.num_ces = 4,
	.ces = {
		{ 
			.key = "file", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u = { .string = ULOGD_AARDVARK_DEFAULT },
		},
		{ 
			.key = "sync", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = ULOGD_AARDVARK_SYNC_DEFAULT },
		},
		{ 
			.key = "server_ip", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u = { .string = ULOGD_AARDVARK_DEFAULT_SERVER_IP },
		},
		{ 
			.key = "buffer_size", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = ULOGD_AARDVARK_BUF_DEFAULT },
		},
	},
};

struct aardvark_instance {
	FILE *of;
        char* buf;
};

struct intr_id {
	char* name;
	unsigned int id;		
};

#define INTR_IDS 	7
static struct ulogd_key aardvark_keys[INTR_IDS] = {
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "raw.pkt" },
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "raw.pktlen" },
	{ .type = ULOGD_RET_UINT16,
	  .flags = ULOGD_RETF_NONE,
	  .name = "ip.totlen" },
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "oob.time.sec" },
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "oob.time.usec" },
	{ .type = ULOGD_RET_UINT8,
	  .flags = ULOGD_RETF_NONE,
	  .name = "oob.family" },
	{ .type = ULOGD_RET_UINT16,
	  .flags = ULOGD_RETF_NONE,
	  .name = "ip6.payloadlen" },
};

#define GET_FLAGS(res, x)	(res[x].u.source->flags)

static int interp_aardvark(struct ulogd_pluginstance *upi)
{
	struct aardvark_instance *pi = (struct aardvark_instance *) &upi->private;
	struct ulogd_key *res = upi->input.keys;
	struct aardvark_sf_pkthdr pchdr;

	pchdr.caplen = ikey_get_u32(&res[1]);

	/* Try to set the len field correctly, if we know the protocol. */
	switch (ikey_get_u8(&res[5])) {
	case 2: /* INET */
		pchdr.len = ikey_get_u16(&res[2]);
		break;
	case 10: /* INET6 -- payload length + header length */
		pchdr.len = ikey_get_u16(&res[6]) + 40;
		break;
	default:
		pchdr.len = pchdr.caplen;
		break;
	}

	if (GET_FLAGS(res, 3) & ULOGD_RETF_VALID
	    && GET_FLAGS(res, 4) & ULOGD_RETF_VALID) {
		pchdr.ts.tv_sec = ikey_get_u32(&res[3]);
		pchdr.ts.tv_usec = ikey_get_u32(&res[4]);
	} else {
		/* use current system time */
		struct timeval tv;
		gettimeofday(&tv, NULL);

		pchdr.ts.tv_sec = tv.tv_sec;
		pchdr.ts.tv_usec = tv.tv_usec;
	}

        if(pi->buf == NULL) {
		ulogd_log(ULOGD_ERROR, "pi->buf is NULL\n");
		return ULOGD_IRET_ERR;
        }

        /* Convert ts to millisecond */
        uint64_t time_in_millisecond = (uint64_t)pchdr.ts.tv_sec * 1000 + (uint64_t)pchdr.ts.tv_usec / 1000;
        uint32_t mlen = upi->config_kset->ces[3].u.value / 2;
        mlen = mlen > pchdr.caplen ? pchdr.caplen : mlen;
        
        /* Convert binary data in res[0] to hex format in order to be transferred by flumeNG  */
        char* cpt = (char*)(ikey_get_ptr(&res[0]));
        int digit;
        char* bptr = pi->buf;
        uint32_t i = 0;
        for(; i < mlen; i++, cpt++)
        {
            digit = (*cpt >> 4) & 0xf;
            *bptr++ = ( digit > 9 ) ? digit + 'a' - 10 : digit + '0';
      
            digit = *cpt & 0xf;
            *bptr++ = ( digit > 9 ) ? digit + 'a' - 10 : digit + '0';
        }
        *bptr = '\0';

        if (fprintf(pi->of, "%lu %s %s\n", time_in_millisecond, upi->config_kset->ces[2].u.string, pi->buf) < 0) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return ULOGD_IRET_ERR;
	}

	if (upi->config_kset->ces[1].u.value)
		fflush(pi->of);

	return ULOGD_IRET_OK;
}

static int append_create_outfile(struct ulogd_pluginstance *upi)
{
	struct aardvark_instance *pi = (struct aardvark_instance *) &upi->private;
	char *filename = upi->config_kset->ces[0].u.string;
	struct stat st_dummy;
	int exist = 0;

	if (stat(filename, &st_dummy) == 0 && st_dummy.st_size > 0)
		exist = 1;

	if (!exist) {
		pi->of = fopen(filename, "w");
		if (!pi->of) {
			ulogd_log(ULOGD_ERROR, "can't open aardvark file %s: %s\n",
				  filename,
				  strerror(errno));
			return -EPERM;
		}
	} else {
		pi->of = fopen(filename, "a");
		if (!pi->of) {
			ulogd_log(ULOGD_ERROR, "can't open aardvark file %s: %s\n", 
				filename,
				strerror(errno));
			return -EPERM;
		}		
	}

	return 0;
}

static void signal_aardvark(struct ulogd_pluginstance *upi, int signal)
{
	struct aardvark_instance *pi = (struct aardvark_instance *) &upi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "reopening capture file\n");
		fclose(pi->of);
		append_create_outfile(upi);
		break;
	default:
		break;
	}
}

static int configure_aardvark(struct ulogd_pluginstance *upi,
			  struct ulogd_pluginstance_stack *stack)
{
	return config_parse_file(upi->id, upi->config_kset);
}

static int start_aardvark(struct ulogd_pluginstance *upi)
{
	struct aardvark_instance *pi = (struct aardvark_instance *) &upi->private;
	pi->buf = (char*)malloc(upi->config_kset->ces[3].u.value + 1);
        if(pi->buf == NULL)
        {
            ulogd_log(ULOGD_ERROR, "Error during malloc, size:%d bytes", upi->config_kset->ces[3].u.value);
            return ULOGD_IRET_ERR;
        }       

	return append_create_outfile(upi);
}

static int stop_aardvark(struct ulogd_pluginstance *upi)
{
	struct aardvark_instance *pi = (struct aardvark_instance *) &upi->private;

        if (pi->buf)
                free(pi->buf);

	if (pi->of)
		fclose(pi->of);

	return 0;
}

static struct ulogd_plugin aardvark_plugin = {
	.name = "AARDVARK",
	.input = {
		.keys = aardvark_keys,
		.num_keys = ARRAY_SIZE(aardvark_keys),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &aardvark_kset,
	.priv_size	= sizeof(struct aardvark_instance),

	.configure	= &configure_aardvark,
	.start		= &start_aardvark,
	.stop		= &stop_aardvark,
	.signal		= &signal_aardvark,
	.interp		= &interp_aardvark,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&aardvark_plugin);
}
