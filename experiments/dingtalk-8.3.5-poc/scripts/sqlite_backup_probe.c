#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef int (*open_v2_fn)(const char *, sqlite3 **, int, const char *);
typedef int (*prepare_v2_fn)(sqlite3 *, const char *, int, sqlite3_stmt **,
                             const char **);
typedef int (*prepare_v3_fn)(sqlite3 *, const char *, int, unsigned int,
                             sqlite3_stmt **, const char **);

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static sqlite3 *g_target = NULL;
static atomic_int g_backup_state = 0; /* 0 waiting, 1 running, 2 done, 3 failed */

typedef int (*aes_set_decrypt_key_fn)(const unsigned char *, int, void *);
typedef void (*aes_decrypt_fn)(const unsigned char *, unsigned char *,
                               const void *);
typedef void (*aes_cbc_encrypt_fn)(const unsigned char *, unsigned char *, size_t,
                                   const void *, unsigned char *, int);

struct aes_key_record {
  const void *schedule;
  int bits;
  unsigned char raw[32];
};

static struct aes_key_record g_aes_keys[64];
static size_t g_aes_key_count = 0;
static atomic_int g_aes_capture_done = 0;

static intptr_t main_executable_slide(void) {
  uint32_t count = _dyld_image_count();
  for (uint32_t index = 0; index < count; ++index) {
    const struct mach_header *header = _dyld_get_image_header(index);
    if (header != NULL && header->filetype == MH_EXECUTE) {
      return _dyld_get_image_vmaddr_slide(index);
    }
  }
  return 0;
}

static void *force_im_initialize(void *unused) {
  (void)unused;
  sleep(2);

  const char *source_prefix = getenv("DINGTALK_POC_SOURCE_PREFIX");
  if (source_prefix == NULL || source_prefix[0] != '/' ||
      strstr(source_prefix, "/work/") == NULL || chdir(source_prefix) != 0) {
    fprintf(stderr,
            "[dingtalk-poc] isolated DB directory rejected or unavailable: %s\n",
            source_prefix == NULL ? "(unset)" : strerror(errno));
    return NULL;
  }
  fprintf(stderr, "[dingtalk-poc] isolated DB working directory selected\n");

  intptr_t slide = main_executable_slide();
  typedef void *(*manager_getter_fn)(void);
  typedef int (*manager_initialize_fn)(void *, void *);
  manager_getter_fn get_manager =
      (manager_getter_fn)(slide + (intptr_t)0x1014fbcbc);
  manager_initialize_fn initialize =
      (manager_initialize_fn)(slide + (intptr_t)0x1014fd9d0);

  void *manager = get_manager();
  void *context = calloc(512, 1);
  if (manager == NULL || context == NULL) {
    fprintf(stderr, "[dingtalk-poc] forced IM init prerequisites missing\n");
    return NULL;
  }
  fprintf(stderr, "[dingtalk-poc] invoking isolated IM database initialization\n");
  int rc = initialize(manager, context);
  fprintf(stderr, "[dingtalk-poc] isolated IM initialization returned rc=%d\n", rc);
  return NULL;
}

__attribute__((constructor)) static void start_optional_force_im_init(void) {
  const char *enabled = getenv("DINGTALK_POC_FORCE_IM_INIT");
  if (enabled == NULL || strcmp(enabled, "1") != 0) {
    return;
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, force_im_initialize, NULL) == 0) {
    pthread_detach(thread);
  }
}

static int parse_hex_prefix(unsigned char output[16]) {
  const char *hex = getenv("DINGTALK_POC_CIPHER_PREFIX_HEX");
  if (hex == NULL || strlen(hex) != 32) {
    return 0;
  }
  for (size_t i = 0; i < 16; ++i) {
    char pair[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
    char *end = NULL;
    long value = strtol(pair, &end, 16);
    if (end == NULL || *end != '\0' || value < 0 || value > 255) {
      return 0;
    }
    output[i] = (unsigned char)value;
  }
  return 1;
}

static int write_capture(const char *suffix, const void *data, size_t size) {
  const char *prefix = getenv("DINGTALK_POC_AES_CAPTURE_PREFIX");
  if (prefix == NULL || prefix[0] == '\0') {
    return -1;
  }
  size_t path_len = strlen(prefix) + strlen(suffix) + 1;
  char *path = calloc(path_len, 1);
  if (path == NULL) {
    return -1;
  }
  snprintf(path, path_len, "%s%s", prefix, suffix);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
  int result = -1;
  if (fd >= 0) {
    ssize_t written = write(fd, data, size);
    result = written == (ssize_t)size ? 0 : -1;
    close(fd);
  }
  free(path);
  return result;
}

int AES_set_decrypt_key(const unsigned char *user_key, int bits, void *schedule) {
  static aes_set_decrypt_key_fn real_fn = NULL;
  if (real_fn == NULL) {
    real_fn = (aes_set_decrypt_key_fn)dlsym(RTLD_NEXT, "AES_set_decrypt_key");
  }
  int rc = real_fn(user_key, bits, schedule);
  if (rc == 0 && user_key != NULL && schedule != NULL && bits > 0 && bits <= 256 &&
      bits % 8 == 0) {
    pthread_mutex_lock(&g_lock);
    if (g_aes_key_count < sizeof(g_aes_keys) / sizeof(g_aes_keys[0])) {
      struct aes_key_record *record = &g_aes_keys[g_aes_key_count++];
      record->schedule = schedule;
      record->bits = bits;
      memcpy(record->raw, user_key, (size_t)bits / 8);
    }
    pthread_mutex_unlock(&g_lock);
  }
  return rc;
}

void AES_decrypt(const unsigned char *input, unsigned char *output,
                 const void *schedule) {
  static aes_decrypt_fn real_fn = NULL;
  if (real_fn == NULL) {
    real_fn = (aes_decrypt_fn)dlsym(RTLD_NEXT, "AES_decrypt");
  }

  unsigned char wanted[16];
  int candidate = input != NULL && output != NULL &&
                  parse_hex_prefix(wanted) && memcmp(input, wanted, 16) == 0;
  real_fn(input, output, schedule);

  int expected = 0;
  if (!candidate ||
      !atomic_compare_exchange_strong(&g_aes_capture_done, &expected, 1)) {
    return;
  }

  static const unsigned char sqlite_header[16] = "SQLite format 3";
  unsigned char derived_iv[16];
  for (size_t i = 0; i < sizeof(derived_iv); ++i) {
    derived_iv[i] = output[i] ^ sqlite_header[i];
  }
  write_capture(".iv.bin", derived_iv, sizeof(derived_iv));
  write_capture(".first-block-pre-xor.bin", output, 16);

  int raw_key_written = 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_aes_key_count; ++i) {
    if (g_aes_keys[i].schedule == schedule) {
      raw_key_written =
          write_capture(".raw-key.bin", g_aes_keys[i].raw,
                        (size_t)g_aes_keys[i].bits / 8) == 0;
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  if (!raw_key_written) {
    write_capture(".schedule.bin", schedule, 244);
  }

  const char *metadata = raw_key_written
                             ? "primitive=AES_decrypt\nraw_key=captured\n"
                             : "primitive=AES_decrypt\nraw_key=not-captured\n";
  write_capture(".metadata.txt", metadata, strlen(metadata));
  fprintf(stderr, "[dingtalk-poc] AES first-block capture completed\n");
}

void AES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     size_t length, const void *schedule, unsigned char *ivec,
                     int encrypt) {
  static aes_cbc_encrypt_fn real_fn = NULL;
  if (real_fn == NULL) {
    real_fn = (aes_cbc_encrypt_fn)dlsym(RTLD_NEXT, "AES_cbc_encrypt");
  }

  unsigned char wanted[16];
  unsigned char input_prefix[16];
  unsigned char iv_before[16];
  int candidate =
      encrypt == 0 && input != NULL && output != NULL && ivec != NULL &&
      length >= 16 && parse_hex_prefix(wanted) &&
      (memcpy(input_prefix, input, 16), memcmp(input_prefix, wanted, 16) == 0);
  if (candidate) {
    memcpy(iv_before, ivec, 16);
  }

  real_fn(input, output, length, schedule, ivec, encrypt);

  int expected = 0;
  if (!candidate || memcmp(output, "SQLite format 3\0", 16) != 0 ||
      !atomic_compare_exchange_strong(&g_aes_capture_done, &expected, 1)) {
    return;
  }

  write_capture(".iv.bin", iv_before, sizeof(iv_before));
  size_t header_size = length < 100 ? length : 100;
  write_capture(".page-header.bin", output, header_size);

  int raw_key_written = 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_aes_key_count; ++i) {
    if (g_aes_keys[i].schedule == schedule) {
      raw_key_written =
          write_capture(".raw-key.bin", g_aes_keys[i].raw,
                        (size_t)g_aes_keys[i].bits / 8) == 0;
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  if (!raw_key_written) {
    /* OpenSSL AES_KEY is 240 bytes of round keys plus a 4-byte round count. */
    write_capture(".schedule.bin", schedule, 244);
  }

  char metadata[128];
  int metadata_len = snprintf(metadata, sizeof(metadata),
                              "length=%zu\nraw_key=%s\n", length,
                              raw_key_written ? "captured" : "not-captured");
  if (metadata_len > 0) {
    write_capture(".metadata.txt", metadata, (size_t)metadata_len);
  }
  fprintf(stderr, "[dingtalk-poc] AES page-header capture completed\n");
}

static int path_is_target(const char *path) {
  const char *prefix = getenv("DINGTALK_POC_SOURCE_PREFIX");
  const char *wanted_base = getenv("DINGTALK_POC_BASENAME");
  if (path == NULL || prefix == NULL || prefix[0] == '\0') {
    return 0;
  }
  if (wanted_base == NULL || wanted_base[0] == '\0') {
    wanted_base = "dingtalk.db";
  }
  size_t prefix_len = strlen(prefix);
  size_t path_len = strlen(path);
  const char *base = strrchr(path, '/');
  base = base == NULL ? path : base + 1;
  return path_len > prefix_len && strncmp(path, prefix, prefix_len) == 0 &&
         strcmp(base, wanted_base) == 0;
}

static void remember_target(sqlite3 *db, const char *path) {
  if (db == NULL || !path_is_target(path)) {
    return;
  }
  pthread_mutex_lock(&g_lock);
  if (g_target == NULL) {
    g_target = db;
    fprintf(stderr, "[dingtalk-poc] isolated target database handle captured\n");
  }
  pthread_mutex_unlock(&g_lock);
}

static void attempt_backup(sqlite3 *source) {
  int expected = 0;
  if (source == NULL || source != g_target ||
      !atomic_compare_exchange_strong(&g_backup_state, &expected, 1)) {
    return;
  }

  const char *output = getenv("DINGTALK_POC_OUTPUT");
  if (output == NULL || output[0] == '\0' || access(output, F_OK) == 0) {
    fprintf(stderr, "[dingtalk-poc] output missing or already exists\n");
    atomic_store(&g_backup_state, 3);
    return;
  }

  size_t partial_len = strlen(output) + sizeof(".partial");
  char *partial = calloc(partial_len, 1);
  if (partial == NULL) {
    atomic_store(&g_backup_state, 3);
    return;
  }
  snprintf(partial, partial_len, "%s.partial", output);
  unlink(partial);

  sqlite3 *destination = NULL;
  int rc = sqlite3_open_v2(partial, &destination,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                           "unix");
  sqlite3_backup *backup = NULL;
  if (rc == SQLITE_OK) {
    backup = sqlite3_backup_init(destination, "main", source, "main");
    rc = backup == NULL ? sqlite3_errcode(destination) : SQLITE_OK;
  }
  if (backup != NULL) {
    for (int tries = 0; tries < 100; ++tries) {
      rc = sqlite3_backup_step(backup, -1);
      if (rc == SQLITE_DONE) {
        break;
      }
      if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED) {
        break;
      }
      sqlite3_sleep(10);
    }
    int finish_rc = sqlite3_backup_finish(backup);
    if (rc == SQLITE_DONE && finish_rc != SQLITE_OK) {
      rc = finish_rc;
    }
  }
  if (destination != NULL) {
    int close_rc = sqlite3_close(destination);
    if (rc == SQLITE_DONE && close_rc != SQLITE_OK) {
      rc = close_rc;
    }
  }

  if (rc == SQLITE_DONE && chmod(partial, S_IRUSR | S_IWUSR) == 0 &&
      rename(partial, output) == 0) {
    fprintf(stderr, "[dingtalk-poc] plaintext backup completed\n");
    atomic_store(&g_backup_state, 2);
  } else {
    fprintf(stderr, "[dingtalk-poc] backup failed rc=%d\n", rc);
    unlink(partial);
    atomic_store(&g_backup_state, 3);
  }
  free(partial);
}

int sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags,
                    const char *zVfs) {
  static open_v2_fn real_fn = NULL;
  if (real_fn == NULL) {
    real_fn = (open_v2_fn)dlsym(RTLD_NEXT, "sqlite3_open_v2");
  }
  int rc = real_fn(filename, ppDb, flags, zVfs);
  if (rc == SQLITE_OK && ppDb != NULL) {
    remember_target(*ppDb, filename);
  }
  return rc;
}

int sqlite3_prepare_v2(sqlite3 *db, const char *sql, int nByte,
                       sqlite3_stmt **stmt, const char **tail) {
  static prepare_v2_fn real_fn = NULL;
  if (real_fn == NULL) {
    real_fn = (prepare_v2_fn)dlsym(RTLD_NEXT, "sqlite3_prepare_v2");
  }
  int rc = real_fn(db, sql, nByte, stmt, tail);
  if (rc == SQLITE_OK) {
    attempt_backup(db);
  }
  return rc;
}

int sqlite3_prepare_v3(sqlite3 *db, const char *sql, int nByte,
                       unsigned int prepFlags, sqlite3_stmt **stmt,
                       const char **tail) {
  static prepare_v3_fn real_fn = NULL;
  if (real_fn == NULL) {
    real_fn = (prepare_v3_fn)dlsym(RTLD_NEXT, "sqlite3_prepare_v3");
  }
  int rc = real_fn(db, sql, nByte, prepFlags, stmt, tail);
  if (rc == SQLITE_OK) {
    attempt_backup(db);
  }
  return rc;
}
