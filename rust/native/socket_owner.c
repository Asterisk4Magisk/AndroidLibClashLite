// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

#include "../../go/native/flowmeta/owner_diag.h"
#include <pthread.h>
#ifdef __ANDROID__
#include <android/api-level.h>
#endif

int asterisk_android_api_level(void) {
#ifdef __ANDROID__
    return android_get_device_api_level();
#else
    return 0;
#endif
}

static struct flow_owner_query queries[4];
static pthread_mutex_t locks[4] = {
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,
};

int asterisk_socket_owner(int udp, const unsigned char *source, uint16_t source_port,
    const unsigned char *destination, uint16_t destination_port, uint32_t *uid) {
    int index = (udp ? 2 : 0) + !flow_owner_is_v4(source);
    uint32_t inode;
    pthread_mutex_lock(&locks[index]);
    int result = flow_owner_lookup(&queries[index], udp, source, source_port,
        destination, destination_port, uid, &inode);
    pthread_mutex_unlock(&locks[index]);
    return result;
}
