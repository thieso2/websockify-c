#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int _test_pass = 0;
static int _test_fail = 0;
static int _test_count = 0;

#define TEST(name) static void name(void)

#define RUN_TEST(name) do { \
    _test_count++; \
    printf("  %-60s", #name); \
    fflush(stdout); \
    name(); \
    printf(" OK\n"); \
    _test_pass++; \
} while (0)

#define TEST_MAIN_BEGIN \
    int main(int argc, char **argv) { \
        (void)argc; (void)argv; \
        printf("Running %s\n", __FILE__);

#define TEST_MAIN_END \
        printf("\n%d/%d tests passed", _test_pass, _test_count); \
        if (_test_fail > 0) printf(", %d FAILED", _test_fail); \
        printf("\n"); \
        return _test_fail > 0 ? 1 : 0; \
    }

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf(" FAIL\n    %s:%d: ASSERT(%s) failed\n", __FILE__, __LINE__, #cond); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        printf(" FAIL\n    %s:%d: ASSERT_EQ(%s, %s) => %lld != %lld\n", \
               __FILE__, __LINE__, #a, #b, _a, _b); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_NEQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a == _b) { \
        printf(" FAIL\n    %s:%d: ASSERT_NEQ(%s, %s) => both %lld\n", \
               __FILE__, __LINE__, #a, #b, _a); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
    const char *_a = (a), *_b = (b); \
    if (_a == NULL && _b == NULL) break; \
    if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) { \
        printf(" FAIL\n    %s:%d: ASSERT_STR_EQ(%s, %s) => \"%s\" != \"%s\"\n", \
               __FILE__, __LINE__, #a, #b, _a ? _a : "(null)", _b ? _b : "(null)"); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_NULL(a) do { \
    if ((a) != NULL) { \
        printf(" FAIL\n    %s:%d: ASSERT_NULL(%s) => not null\n", __FILE__, __LINE__, #a); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_NOT_NULL(a) do { \
    if ((a) == NULL) { \
        printf(" FAIL\n    %s:%d: ASSERT_NOT_NULL(%s) => null\n", __FILE__, __LINE__, #a); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf(" FAIL\n    %s:%d: ASSERT_MEM_EQ(%s, %s, %d) => mismatch\n", \
               __FILE__, __LINE__, #a, #b, (int)(len)); \
        _test_fail++; _test_pass--; \
        return; \
    } \
} while (0)

#define ASSERT_TRUE(a)  ASSERT(a)
#define ASSERT_FALSE(a) ASSERT(!(a))

#endif /* TEST_COMMON_H */
