/*
 * Copyright (c) 2015, Scott K Logan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of libCEC nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL SCOTT K LOGAN BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <time.h>
#include <conio.h>
#include <fcntl.h>
#include <io.h>
#include <cecc.h>
#else
#include <sys/time.h>
#include <termios.h>
#include <libcec/cecc.h>
#endif

#ifdef _WIN32
#pragma pack(push,1)
#define __attribute__(x)
#pragma warning( push )
#pragma warning( disable : 4200 )
#endif

typedef struct pcap_hdr_s {
    unsigned int magic_number;         /* magic number */
    unsigned short int version_major;  /* major version number */
    unsigned short int version_minor;  /* minor version number */
    int  thiszone;                     /* GMT to local correction */
    unsigned int sigfigs;              /* accuracy of timestamps */
    unsigned int snaplen;              /* max length of captured packets, in octets */
    unsigned int network;              /* data link type */
} __attribute__((packed)) pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    unsigned int ts_sec;         /* timestamp seconds */
    unsigned int ts_usec;        /* timestamp microseconds */
    unsigned int incl_len;       /* number of octets of packet saved in file */
    unsigned int orig_len;       /* actual length of packet */
    unsigned char data[];
} __attribute__((packed)) pcaprec_hdr_t;

#ifdef _WIN32
#pragma warning( pop )
#pragma pack(pop)
#endif

typedef struct priv_data {
    FILE *fh;
#ifdef _WIN32
    HANDLE fh_lock;
#endif
} priv_data_t;

static const pcap_hdr_t header =
{
    .magic_number = 0xa1b2c3d4,
    .version_major = 0x0002,
    .version_minor = 0x0004,
    .thiszone = 0x00000000,
    .sigfigs = 0x00000000,
    .snaplen = 0x00000010,
    .network = 0x0108,
};

#ifdef _WIN32
typedef int (*CEC_INITIALISE)(libcec_configuration *);
typedef int8_t (*CEC_FIND_ADAPTERS)(cec_adapter *, uint8_t, const char *);
typedef int (*CEC_ENABLE_CALLBACKS)(void *, ICECCallbacks *);
typedef int (*CEC_OPEN)(const char *, uint32_t);
typedef void (*CEC_CLOSE)(void);
typedef void (*CEC_DESTROY)(void);
HINSTANCE hDLL = NULL;
CEC_INITIALISE wr_cec_initialise = NULL;
CEC_FIND_ADAPTERS wr_cec_find_adapters = NULL;
CEC_ENABLE_CALLBACKS wr_cec_enable_callbacks = NULL;
CEC_OPEN wr_cec_open = NULL;
CEC_CLOSE wr_cec_close = NULL;
CEC_DESTROY wr_cec_destroy = NULL;
#else
#define wr_cec_initialise cec_initialise
#define wr_cec_find_adapters cec_find_adapters
#define wr_cec_enable_callbacks cec_enable_callbacks
#define wr_cec_open cec_open
#define wr_cec_close cec_close
#define wr_cec_destroy cec_destroy
#endif

int cecmessage(void *priv_void, const cec_log_message message)
{
    priv_data_t *priv = (priv_data_t *)priv_void;
    unsigned char i;
    unsigned char buf[sizeof(pcaprec_hdr_t) + 16];
    pcaprec_hdr_t *pkt = (pcaprec_hdr_t *)buf;

    if (message.level != CEC_LOG_TRAFFIC)
    {
        return 0;
    }

#ifdef _WIN32
    FILETIME tm;
    ULONGLONG t;
#if defined(NTDDI_WIN8) && NTDDI_VERSION >= NTDDI_WIN8
    /* Windows 8, Windows Server 2012 and later. ---------------- */
    GetSystemTimePreciseAsFileTime(&tm);
#else
    /* Windows 2000 and later. ---------------------------------- */
    GetSystemTimeAsFileTime(&tm);
#endif
    t = ((ULONGLONG)tm.dwHighDateTime << 32) | (ULONGLONG)tm.dwLowDateTime;
    pkt->ts_sec = (int)(t / 10000000);
    pkt->ts_usec = (t % 10000000) / 10;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pkt->ts_sec = tv.tv_sec;
    pkt->ts_usec = tv.tv_usec;
#endif

    const char *msg_ptr = message.message + 3;
    const char *msg_end = message.message + strlen(message.message);

    for (i = 0; i < 16 && msg_ptr < msg_end; i++)
    {
        if (sscanf(msg_ptr, "%hhx", &pkt->data[i]) != 1)
        {
            fprintf(stderr, "Failed to parse a byte!\r\n");
        }

        msg_ptr += 3;
    }

    pkt->incl_len = i;
    pkt->orig_len = i;

#ifdef _WIN32
    if (WaitForSingleObject(priv->fh_lock, INFINITE) == WAIT_OBJECT_0)
#endif
    {
        fwrite(buf, 1, sizeof(pcaprec_hdr_t) + i, priv->fh);
        fflush(priv->fh);
#ifdef _WIN32
        ReleaseMutex(priv->fh_lock);
#endif
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    cec_adapter cecdevs;
    libcec_configuration cecconf;
    ICECCallbacks ceccallbacks = { 0x0 };
    priv_data_t priv;

    if (argc == 2)
    {
        priv.fh = fopen(argv[1], "wb");

        if (priv.fh == NULL)
        {
            fprintf(stderr, "Failed to open input file '%s'\r\n", argv[1]);
            ret = EXIT_FAILURE;
            goto exit_close;
        }
    }
    else if (argc < 2)
    {
#ifdef _WIN32
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        priv.fh = stdout;
    }
    else
    {
        fprintf(stderr, "Usage: %s [optional pcap output file]\r\n", argv[0]);
        ret = EXIT_FAILURE;
        goto exit_close;
    }

    memset(&cecconf, 0x0, sizeof(cecconf));
    cecconf.clientVersion = CEC_CLIENT_VERSION_2_1_4;
    ceccallbacks.CBCecLogMessage = &cecmessage;
    cecconf.callbacks = &ceccallbacks;
    cecconf.callbackParam = (void *)&priv;
    cecconf.bMonitorOnly = 1;

#ifdef _WIN32
    priv.fh_lock = CreateMutex(NULL, FALSE, NULL);
    if (priv.fh_lock == NULL)
    {
        fprintf(stderr, "Failed to create mutex\r\n");
        ret = EXIT_FAILURE;
        goto exit_close_file;
    }

    hDLL = LoadLibrary((LPTSTR)L"libcec");
    if (hDLL == NULL)
    {
        fprintf(stderr, "Failed to load libcec.dll\r\n");
        ret = EXIT_FAILURE;
        goto exit_close_file;
    }
    wr_cec_initialise = (CEC_INITIALISE)GetProcAddress(hDLL, "cec_initialise");
    wr_cec_find_adapters = (CEC_FIND_ADAPTERS)GetProcAddress(hDLL, "cec_find_adapters");
    wr_cec_enable_callbacks = (CEC_ENABLE_CALLBACKS)GetProcAddress(hDLL, "cec_enable_callbacks");
    wr_cec_open = (CEC_OPEN)GetProcAddress(hDLL, "cec_open");
    wr_cec_close = (CEC_CLOSE)GetProcAddress(hDLL, "cec_close");
    wr_cec_destroy = (CEC_DESTROY)GetProcAddress(hDLL, "cec_destroy");

    if (wr_cec_initialise == NULL || wr_cec_find_adapters == NULL || wr_cec_enable_callbacks == NULL ||
        wr_cec_open == NULL || wr_cec_close == NULL || wr_cec_destroy == NULL)
    {
        fprintf(stderr, "Failed to load function(s) from libcec.dll\r\n");
        ret = EXIT_FAILURE;
        goto exit_close_file;
    }
#endif

    ret = wr_cec_initialise(&cecconf);
    if (ret < 1)
    {
        fprintf(stderr, "Failed to initialise libcec: %d\r\n", ret);
        ret = EXIT_FAILURE;
        goto exit_close_file;
    }

    ret = wr_cec_enable_callbacks(cecconf.callbackParam, cecconf.callbacks);
    if (ret < 1)
    {
        fprintf(stderr, "Failed to enable callbacks: %d\r\n", ret);
        ret = EXIT_FAILURE;
        goto exit_close_cec;
    }

    ret = wr_cec_find_adapters(&cecdevs, 1, NULL);
    if (ret < 0)
    {
        fprintf(stderr, "Failed to find adapters: %d\r\n", ret);
        ret = EXIT_FAILURE;
        goto exit_close_cec;
    }
    else if (ret == 0)
    {
        fprintf(stderr, "No adapters were found\r\n");
        ret = EXIT_FAILURE;
        goto exit_close_cec;
    }

    fwrite(&header, 1, sizeof(header), priv.fh);
    fflush(priv.fh);

    ret = wr_cec_open(cecdevs.comm, 1000);
    if (ret < 1)
    {
        fprintf(stderr, "Failed to open device \"%s\": %d\r\n", cecdevs.comm, ret);
        ret = EXIT_FAILURE;
        goto exit_close_cec;
    }

    fprintf(stderr, "Device open. Press any key to stop reading...\r\n");
#ifdef _WIN32
    _getch();
#else
    struct termios info;
    tcgetattr(0, &info);          /* get current terminal attirbutes; 0 is the file descriptor for stdin */
    info.c_lflag &= ~ICANON;      /* disable canonical mode */
    info.c_cc[VMIN] = 1;          /* wait until at least one keystroke available */
    info.c_cc[VTIME] = 0;         /* no timeout */
    tcsetattr(0, TCSANOW, &info); /* set immediately */
    getchar();
#endif
    fprintf(stderr, "Closing...\r\n");
    ret = EXIT_SUCCESS;

exit_close_cec:
    wr_cec_close();

    wr_cec_destroy();

#ifdef _WIN32
    if (hDLL != NULL)
    {
        FreeLibrary(hDLL);
    }
#endif

exit_close_file:
#ifdef _WIN32
    if (priv.fh_lock != NULL)
    {
        WaitForSingleObject(priv.fh_lock, INFINITE);
    }
#endif

    if (priv.fh != stdout)
    {
        fclose(priv.fh);
    }

exit_close:
    return ret;
}

