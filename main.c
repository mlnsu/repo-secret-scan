#define _POSIX_C_SOURCE 200809L
/*
 * secret-scan: a small, read-only Git working-tree secret scanner.
 * Build with: cc -std=c11 -O2 -Wall -Wextra -o secret-scan main.c
 */
#define _CRT_SECURE_NO_WARNINGS
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#define CASE_NCMP _strnicmp
#else
#include <strings.h>
#define CASE_NCMP strncasecmp
#endif

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#define CHDIR _chdir
#define GETCWD _getcwd
#define POPEN _popen
#define PCLOSE _pclose
#define FILENO _fileno
#else
#include <unistd.h>
#define CHDIR chdir
#define GETCWD getcwd
#define POPEN popen
#define PCLOSE pclose
#define FILENO fileno
#endif

#define MAX_FILE_SIZE (1024 * 1024)
#define MAX_PATH_BUFFER 32768

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} Buffer;

static int append_bytes(Buffer *buffer, const char *data, size_t length) {
    if (buffer->length + length + 1 > buffer->capacity) {
        size_t next = buffer->capacity ? buffer->capacity : 4096;
        while (next < buffer->length + length + 1) next *= 2;
        char *grown = (char *)realloc(buffer->data, next);
        if (!grown) return 0;
        buffer->data = grown;
        buffer->capacity = next;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return 1;
}

static int read_git_file_list(Buffer *output) {
    FILE *pipe = POPEN("git ls-files --cached --others --exclude-standard -z", "rb");
    if (!pipe) return 0;
#ifdef _WIN32
    _setmode(FILENO(pipe), _O_BINARY);
#endif
    char chunk[8192];
    size_t count;
    int okay = 1;
    while ((count = fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
        if (!append_bytes(output, chunk, count)) {
            okay = 0;
            break;
        }
    }
    int status = PCLOSE(pipe);
    return okay && status == 0;
}

static int skipped_directory(const char *path) {
    static const char *const skipped[] = {
        ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
        "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache", NULL
    };
    const char *part = path;
    for (const char *cursor = path;; ++cursor) {
        if (*cursor != '/' && *cursor != '\\' && *cursor != '\0') continue;
        size_t length = (size_t)(cursor - part);
        for (size_t i = 0; skipped[i]; ++i) {
            if (strlen(skipped[i]) == length && strncmp(part, skipped[i], length) == 0) return 1;
        }
        if (*cursor == '\0') break;
        part = cursor + 1;
    }
    return 0;
}

static int is_link(const char *path) {
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    struct stat info;
    return lstat(path, &info) == 0 && S_ISLNK(info.st_mode);
#endif
}

static int is_word_char(unsigned char value) {
    return isalnum(value) || value == '_';
}

static int starts_at(const char *text, size_t length, size_t at, const char *prefix) {
    size_t n = strlen(prefix);
    return at + n <= length && memcmp(text + at, prefix, n) == 0;
}

static int contains_bytes(const char *text, size_t length, const char *needle) {
    size_t needle_length = strlen(needle);
    if (needle_length > length) return 0;
    for (size_t i = 0; i + needle_length <= length; ++i) {
        if (memcmp(text + i, needle, needle_length) == 0) return 1;
    }
    return 0;
}

static int token_end(const char *text, size_t length, size_t at) {
    return at == length || !is_word_char((unsigned char)text[at]);
}

static int match_fixed_token(const char *line, size_t length, size_t at,
                             const char *prefix, size_t tail_length,
                             int (*valid_tail)(unsigned char)) {
    size_t prefix_length = strlen(prefix);
    if (!starts_at(line, length, at, prefix)) return 0;
    if (at > 0 && is_word_char((unsigned char)line[at - 1])) return 0;
    if (at + prefix_length + tail_length > length) return 0;
    for (size_t i = 0; i < tail_length; ++i) {
        if (!valid_tail((unsigned char)line[at + prefix_length + i])) return 0;
    }
    return token_end(line, length, at + prefix_length + tail_length);
}

static int upper_alnum(unsigned char c) { return (c >= 'A' && c <= 'Z') || isdigit(c); }
static int api_key_char(unsigned char c) { return isalnum(c) || c == '_' || c == '-'; }

static int credential_assignment(const char *line, size_t length) {
    static const char *const keys[] = {
        "api_key", "api-key", "apikey", "access_token", "access-token", "accesstoken",
        "auth_token", "auth-token", "authtoken", "client_secret", "client-secret",
        "clientsecret", "password", "passwd", "secret_key", "secret-key", "secretkey", NULL
    };
    for (size_t i = 0; i < length; ++i) {
        for (size_t k = 0; keys[k]; ++k) {
            size_t n = strlen(keys[k]);
            if (i + n > length || (i && is_word_char((unsigned char)line[i - 1]))) continue;
            size_t j = 0;
            while (j < n && tolower((unsigned char)line[i + j]) == keys[k][j]) ++j;
            if (j != n || (i + n < length && is_word_char((unsigned char)line[i + n]))) continue;
            size_t value = i + n;
            while (value < length && isspace((unsigned char)line[value])) ++value;
            if (value == length || (line[value] != ':' && line[value] != '=')) continue;
            ++value;
            while (value < length && isspace((unsigned char)line[value])) ++value;
            if (value < length && (line[value] == '\'' || line[value] == '"' || line[value] == '`')) ++value;
            size_t start = value;
            while (value < length && (isalnum((unsigned char)line[value]) || strchr("_./+=:@-", line[value]))) ++value;
            if (value - start < 8) continue;
            if (value - start == 8 && CASE_NCMP(line + start, "changeme", 8) == 0) continue;
            if (value - start == 11 && CASE_NCMP(line + start, "placeholder", 11) == 0) continue;
            if (value - start >= 5 && CASE_NCMP(line + start, "your_", 5) == 0) continue;
            return 1;
        }
    }
    return 0;
}

static const char *detect_rule(const char *line, size_t length) {
    if (contains_bytes(line, length, "-----BEGIN PRIVATE KEY-----") ||
        contains_bytes(line, length, "-----BEGIN RSA PRIVATE KEY-----") ||
        contains_bytes(line, length, "-----BEGIN EC PRIVATE KEY-----") ||
        contains_bytes(line, length, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
        contains_bytes(line, length, "-----BEGIN DSA PRIVATE KEY-----")) return "private-key";

    for (size_t i = 0; i < length; ++i) {
        if (match_fixed_token(line, length, i, "AKIA", 16, upper_alnum) ||
            match_fixed_token(line, length, i, "ASIA", 16, upper_alnum)) return "aws-access-key";

        static const char *const gh_prefixes[] = {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", NULL};
        for (size_t p = 0; gh_prefixes[p]; ++p) {
            size_t prefix = strlen(gh_prefixes[p]);
            if (starts_at(line, length, i, gh_prefixes[p]) && (i == 0 || !is_word_char((unsigned char)line[i - 1]))) {
                size_t j = i + prefix;
                while (j < length && (isalnum((unsigned char)line[j]) || line[j] == '_')) ++j;
                if (j - i >= 34 && token_end(line, length, j)) return "github-token";
            }
        }
        if (starts_at(line, length, i, "github_pat_") && (i == 0 || !is_word_char((unsigned char)line[i - 1]))) {
            size_t j = i + 11;
            while (j < length && (isalnum((unsigned char)line[j]) || line[j] == '_')) ++j;
            if (j - i >= 61 && token_end(line, length, j)) return "github-token";
        }
        if (starts_at(line, length, i, "AIza") && (i == 0 || !is_word_char((unsigned char)line[i - 1]))) {
            size_t j = i + 4;
            while (j < length && (isalnum((unsigned char)line[j]) || line[j] == '_' || line[j] == '-')) ++j;
            if (j - i == 39 && token_end(line, length, j)) return "google-api-key";
        }
        if (starts_at(line, length, i, "xox") && (i == 0 || !is_word_char((unsigned char)line[i - 1])) &&
            i + 5 < length && strchr("baprs", line[i + 3]) && line[i + 4] == '-') {
            size_t j = i + 5;
            while (j < length && (isalnum((unsigned char)line[j]) || line[j] == '-')) ++j;
            if (j - (i + 5) >= 10 && token_end(line, length, j)) return "slack-token";
        }
    }
    if (credential_assignment(line, length)) return "credential-assignment";
    for (size_t i = 0; i + 3 < length; ++i) {
        if (!starts_at(line, length, i, "eyJ") || (i && is_word_char((unsigned char)line[i - 1]))) continue;
        size_t dots = 0;
        for (size_t j = i + 3; j < length; ++j) if (line[j] == '.') ++dots;
        if (dots >= 2) return "jwt";
    }
    return NULL;
}

static void scan_file(const char *path, const char *relative, unsigned long *total) {
    if (skipped_directory(relative) || is_link(path)) return;
    FILE *file = fopen(path, "rb");
    if (!file) return;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return; }
    long size = ftell(file);
    if (size < 0 || size > MAX_FILE_SIZE || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return; }
    char *data = (char *)malloc((size_t)size + 1);
    if (!data) { fclose(file); return; }
    size_t read = fread(data, 1, (size_t)size, file);
    fclose(file);
    if (read != (size_t)size || memchr(data, '\0', read)) { free(data); return; }
    data[read] = '\0';

    unsigned long line_number = 1;
    size_t start = 0;
    for (size_t i = 0; i <= read; ++i) {
        if (i != read && data[i] != '\n') continue;
        size_t end = i;
        if (end > start && data[end - 1] == '\r') --end;
        const char *rule = detect_rule(data + start, end - start);
        if (rule) {
            printf("  %s:%lu [%s] [REDACTED]\n", relative, line_number, rule);
            ++*total;
        }
        start = i + 1;
        ++line_number;
    }
    free(data);
}

static int scan_repository(const char *repository) {
    char original[MAX_PATH_BUFFER];
    if (!GETCWD(original, sizeof(original))) {
        fprintf(stderr, "error: cannot read current directory\n");
        return 2;
    }
    if (CHDIR(repository) != 0) {
        fprintf(stderr, "error: cannot open directory: %s\n", repository);
        return 2;
    }
    Buffer files = {0};
    if (!read_git_file_list(&files)) {
        fprintf(stderr, "error: not a Git repository or Git could not list files: %s\n", repository);
        free(files.data);
        CHDIR(original);
        return 2;
    }

    printf("%s:\n", repository);
    unsigned long total = 0;
    size_t offset = 0;
    while (offset < files.length) {
        size_t end = offset;
        while (end < files.length && files.data[end] != '\0') ++end;
        if (end > offset) scan_file(files.data + offset, files.data + offset, &total);
        offset = end + 1;
    }
    if (!total) printf("  No likely secrets found.\n");
    free(files.data);
    CHDIR(original);
    return total ? 1 : 0;
}

int main(int argc, char **argv) {
    unsigned long findings = 0;
    int had_error = 0;
    if (argc == 1) {
        int result = scan_repository(".");
        if (result == 2) return 2;
        return result;
    }
    for (int i = 1; i < argc; ++i) {
        int result = scan_repository(argv[i]);
        if (result == 2) had_error = 1;
        else if (result == 1) findings++;
    }
    if (findings) puts("Review matches; false positives are possible. Values are redacted.");
    return had_error ? 2 : (findings ? 1 : 0);
}
