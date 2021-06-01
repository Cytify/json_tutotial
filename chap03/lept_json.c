#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <string.h>  /* memcpy() */

#include "lept_json.h"

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); ++c->json; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1T09(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct
{
    const char* json;
    char* stack;
    size_t size;
    size_t top;
} lept_context;

/**
 * 返回栈顶指针
 */
static void* lept_context_push(lept_context* c, size_t size)
{
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size)
    {
        if (c->size == 0)
        {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size)
        {
            c->size += c->size >> 1;    /* c->size * 1.5 */
        }
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;

    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size)
{
    assert(c->top >= size);

    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c)
{
    const char* p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    {
        ++p;
    }
    c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type)
{
    EXPECT(c, literal[0]);
    size_t i;
    for (i = 0; literal[i + 1]; ++i)
    {
        if (c->json[i] != literal[i + 1])
        {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;

    return LEPT_PARSE_OK;
}


static int lept_parse_number(lept_context* c, lept_value* v)
{
    /* 数据校验 */
    const char* p = c->json;

    /* 负号 */
    if (*p == '-')
    {
        ++p;
    }

    /* 整数 */
    if (*p == '0')
    {
        ++p;
    }
    else
    {
        if (!ISDIGIT1T09(*p))
        {
            return LEPT_PARSE_INVALID_VALUE;
        }
        for (++p; ISDIGIT(*p); ++p);
    }

    /* 小数 */
    if (*p == '.')
    {
        ++p;
        if (!ISDIGIT(*p))
        {
            return LEPT_PARSE_INVALID_VALUE;
        }
        for (++p; ISDIGIT(*p); ++p);
    }

    /* e E */
    if (*p == 'e' || *p == 'E')
    {
        ++p;
        if (*p == '+' || *p == '-')
        {
            ++p;
        }
        if (!ISDIGIT(*p))
        {
            return LEPT_PARSE_INVALID_VALUE;
        }
        for (++p; ISDIGIT(*p); ++p);
    }

    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE || v->u.n == HUGE_VAL)
    {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    v->type = LEPT_NUMBER;
    c->json = p;
    
    return LEPT_PARSE_OK;
}

#include <stdio.h>
static int lept_parse_string(lept_context* c, lept_value* v)
{
    EXPECT(c, '\"');

    size_t head = c->top;
    size_t len;
    const char* p = c->json;

    for (;;)
    {
        char ch = *p++;
        switch(ch)
        {      
            case '\"':
                len = c->top - head;
                lept_set_string(v, (const char*)lept_context_pop(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                c->top = head;
                return LEPT_PARSE_MISS_QUOTATION_MARK;
            case '\\':
                switch (*p++)
                {
                    case '\"':
                        PUTC(c, '\"'); break;
                    case '\\':
                        PUTC(c, '\\'); break;
                    case '/':
                        PUTC(c, '/'); break;
                    case 'b':
                        PUTC(c, '\b'); break;
                    case 'f':
                        PUTC(c, '\f'); break;
                    case 'n':
                        PUTC(c, '\n'); break;
                    case 'r':
                        PUTC(c, '\r'); break;
                    case 't':
                        PUTC(c, '\t'); break;
                    default:
                        c->top = head;
                        return LEPT_PARSE_INVALID_STRING_ESCAPE;
                }
                break;
            default:
                if ((unsigned char)ch < 0x20)
                {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;
                }
                PUTC(c, ch);
        }
    }
}


static int lept_parse_value(lept_context* c, lept_value* v)
{
    switch (*c->json)
    {
    case 'n':
        return lept_parse_literal(c, v, "null", LEPT_NULL);
    case 't':
        return lept_parse_literal(c, v, "true", LEPT_TRUE);
    case 'f':
        return lept_parse_literal(c, v, "false", LEPT_FALSE);
    case '\0':
        return LEPT_PARSE_EXPECT_VALUE;
    case '\"':
        return lept_parse_string(c, v);
    default:
        return lept_parse_number(c, v);
    }
}

int lept_parse(lept_value* v, const char* json)
{
    assert(v != NULL);

    lept_context c;
    c.stack = NULL;
    c.top = c.size = 0;
    int ret;

    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);

    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK)
    {
        lept_parse_whitespace(&c);
        if (*c.json != '\0')
        {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }

    return ret;
}

void lept_free(lept_value* v)
{
    assert(v != NULL);

    if (v->type == LEPT_STRING)
    {
        free(v->u.s.str);
    }
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v)
{
    assert(v != NULL);

    return v->type;
}


int lept_get_boolean(const lept_value* v)
{   
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));

    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b)
{
    assert(v != NULL);
    
    lept_free(&v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value* v)
{
    assert(v!= NULL && v->type == LEPT_NUMBER);

    return v->u.n;
}

void lept_set_number(lept_value* v, double n)
{
    assert(v != NULL);

    lept_free(&v);
    v->type = LEPT_NUMBER;
    v->u.n = n;
}

const char* lept_get_string(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_STRING);

    return v->u.s.str;
}

size_t lept_get_string_length(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_STRING);

    return v->u.s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));

    lept_free(v);
    v->u.s.str = (char*) malloc(len + 1);
    memcpy(v->u.s.str, s, len);
    v->u.s.str[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}