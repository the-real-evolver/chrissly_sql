//------------------------------------------------------------------------------
/**
    chrissly_sql.h

    A single-header file library that implements a minimal sql server
    and client.

    The goal is to support the SQL-86 standard. The implementation will primarily
    be created from the specification available here:
    https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub127.pdf

    Add this line:
        #define CHRISSLY_SQL_IMPLEMENTATION
    before you include this file in *one* C or C++ file to create the implementation.

    Implementation details
    ======================

    Three allocations for every table:

      - one realloc for the table header when a new table is added to the tables array
      - one realloc when a new column is added to the column array of the table
      - one realloc when a new row is added to the table

    (C) 2024 Christian Bleicher
*/
//------------------------------------------------------------------------------
#ifndef INCLUDE_CHRISSLY_SQL_H
#define INCLUDE_CHRISSLY_SQL_H

// error codes, returned from every function
enum chrissly_sql_error_code
{
    CHRISSLY_SQL_OK,
    CHRISSLY_SQL_ERR
};
typedef unsigned int chrissly_sql_error;

typedef void(*chrissly_sql_query_callback)(size_t, char**, char**, void*);

// initialise server and listen for client connections
chrissly_sql_error chrissly_sql_server_open(void);
// close connections to clients
chrissly_sql_error chrissly_sql_server_close(void);
chrissly_sql_error chrissly_sql_server_create_db(char const* file_name);
chrissly_sql_error chrissly_sql_server_load_db(char const* file_name);
chrissly_sql_error chrissly_sql_server_save_db(void);
// executes query and waits for the result
chrissly_sql_error chrissly_sql_server_query(char const* query, chrissly_sql_query_callback cb, void* user_data);

// connects client to the sql server at the given ip-address/hostname
chrissly_sql_error chrissly_sql_client_connect(char const* ip_address);
// close connection to server
chrissly_sql_error chrissly_sql_client_disconnect(void);
// sends query and waits for the result (blocking)
chrissly_sql_error chrissly_sql_client_query(char const* query, chrissly_sql_query_callback cb, void* user_data);

#endif

//------------------------------------------------------------------------------
//
// Implementation
//
//------------------------------------------------------------------------------
#ifdef CHRISSLY_SQL_IMPLEMENTATION

//------------------------------------------------------------------------------
// General platform agnostic stuff
//------------------------------------------------------------------------------
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>

#ifndef CHRISSLY_SQL_LOG
static void
chrissly_sql_log(const char* const msg, ...)
{
    char message[256U];
    va_list args = NULL;
    va_start(args, msg);
    vsnprintf(message, 256U, msg, args);
    va_end(args);
    printf("chrissly_sql: %s", message);
}
#define CHRISSLY_SQL_LOG(...) chrissly_sql_log(__VA_ARGS__)
#endif

#define CHRISSLY_SQL_UNREFERENCED_PARAMETER(P) (P)

#define DEFAULT_BUFLEN 512U
#define MAX_CONNECTIONS 4U

static char query_results[MAX_CONNECTIONS][DEFAULT_BUFLEN];

static void
server_query_result_callback(size_t count, char** columns, char** values, void* user_data)
{
    CHRISSLY_SQL_UNREFERENCED_PARAMETER(values);
    CHRISSLY_SQL_UNREFERENCED_PARAMETER(count);
    (void)strcpy_s(query_results[(uintptr_t)user_data], DEFAULT_BUFLEN, columns[0U]);
}

//------------------------------------------------------------------------------
// SQL definitions
//------------------------------------------------------------------------------
// see chapter "5.3 <token>"
#define MAX_IDENTIFIER_LENGTH 18U
#define SEPARATORS " \n"

// specify the data types (see chapter "5.5 <data type>")
enum data_type
{
    // CHARACTER [(<length>)], CHARACTER is equivalent to CHARACTER(1)
    // implementation definition: char
    DT_CHARACTER,
    DT_CHAR = DT_CHARACTER,
    // NUMERIC [(<precision> [,< scale >])], fixed-point numeric
    // implementation definition: ? Todo
    DT_NUMERIC,
    // DECIMAL [(<precision> [,< scale >])], fixed-point numeric
    // implementation definition: ? Todo
    DT_DECIMAL,
    DT_DEC = DT_DECIMAL,
    // signed whole number with a scale of zero, must be greater than or equal to the precision of SMALLINT
    // implementation definition: int32_t
    DT_INTEGER,
    DT_INT = DT_INTEGER,
    // signed whole number with a scale of zero, precision must be less than or equal to the precision of INT
    // implementation definition: int8_t
    DT_SMALLINT,
    // FLOAT [(<precision>)], FLOAT(24) is equivalent to 32Bit IEEE float
    // implementation definition: ? Todo
    DT_FLOAT,
    // signed floating-point numeric, must be less than the precision defined for DOUBLE
    // implementation definition: float
    DT_REAL,
    // DOUBLE PRECISION, signed floating-point numeric, must be greater than the precision defined for REAL
    // implementation definition: double
    DT_DOUBLE
};

// specify the key words (see chapter "5.3 <token>")
enum key_word
{
    KW_ALL,
    KW_AND,
    KW_ANY,
    KW_AS,
    KW_ASC,
    KW_AUTHORIZATION,
    KW_AVG,
    KW_BEGIN,
    KW_BETWEEN,
    KW_BY,
    KW_CHAR,
    KW_CHARACTER,
    KW_CHECK,
    KW_CLOSE,
    KW_COBOL,
    KW_COMMIT,
    KW_CONTINUE,
    KW_COUNT,
    KW_CREATE,
    KW_CURRENT,
    KW_CURSOR,
    KW_DEC,
    KW_DECIMAL,
    KW_DECLARE,
    KW_DELETE,
    KW_DESC,
    KW_DISTINCT,
    KW_DOUBLE,
    KW_END,
    KW_ESCAPE,
    KW_EXEC,
    KW_EXISTS,
    KW_FETCH,
    KW_FLOAT,
    KW_FOR,
    KW_FORTRAN,
    KW_FOUND,
    KW_FROM,
    KW_GO,
    KW_GOTO,
    KW_GRANT,
    KW_GROUP,
    KW_HAVING,
    KW_IN,
    KW_INDICATOR,
    KW_INSERT,
    KW_INT,
    KW_INTEGER,
    KW_INTO,
    KW_IS,
    KW_LANGUAGE,
    KW_LIKE,
    KW_MAX,
    KW_MIN,
    KW_MODULE,
    KW_NOT,
    KW_NULL,
    KW_NUMERIC,
    KW_OF,
    KW_ON,
    KW_OPEN,
    KW_OPTION,
    KW_OR,
    KW_ORDER,
    KW_PASCAL,
    KW_PLI,
    KW_PRECISION,
    KW_PRIVILEGES,
    KW_PROCEDURE,
    KW_PUBLIC,
    KW_REAL,
    KW_ROLLBACK,
    KW_SCHEMA,
    KW_SECTION,
    KW_SELECT,
    KW_SET,
    KW_SMALLINT,
    KW_SOME,
    KW_SQL,
    KW_SQLCODE,
    KW_SQLERROR,
    KW_SUM,
    KW_TABLE,
    KW_TO,
    KW_UNION,
    KW_UNIQUE,
    KW_UPDATE,
    KW_USER,
    KW_VALUES,
    KW_VIEW,
    KW_WHENEVER,
    KW_WHERE,
    KW_WITH,
    KW_WORK,
    NUM_KEYWORDS
};

const char* key_words[NUM_KEYWORDS] =
{
    "ALL",
    "AND",
    "ANY",
    "AS",
    "ASC",
    "AUTHORIZATION",
    "AVG",
    "BEGIN",
    "BETWEEN",
    "BY",
    "CHAR",
    "CHARACTER",
    "CHECK",
    "CLOSE",
    "COBOL",
    "COMMIT",
    "CONTINUE",
    "COUNT",
    "CREATE",
    "CURRENT",
    "CURSOR",
    "DEC",
    "DECIMAL",
    "DECLARE",
    "DELETE",
    "DESC",
    "DISTINCT",
    "DOUBLE",
    "END",
    "ESCAPE",
    "EXEC",
    "EXISTS",
    "FETCH",
    "FLOAT",
    "FOR",
    "FORTRAN",
    "FOUND",
    "FROM",
    "GO",
    "GOTO",
    "GRANT",
    "GROUP",
    "HAVING",
    "IN",
    "INDICATOR",
    "INSERT",
    "INT",
    "INTEGER",
    "INTO",
    "IS",
    "LANGUAGE",
    "LIKE",
    "MAX",
    "MIN",
    "MODULE",
    "NOT",
    "NULL",
    "NUMERIC",
    "OF",
    "ON",
    "OPEN",
    "OPTION",
    "OR",
    "ORDER",
    "PASCAL",
    "PLI",
    "PRECISION",
    "PRIVILEGES",
    "PROCEDURE",
    "PUBLIC",
    "REAL",
    "ROLLBACK",
    "SCHEMA",
    "SECTION",
    "SELECT",
    "SET",
    "SMALLINT",
    "SOME",
    "SQL",
    "SQLCODE",
    "SQLERROR",
    "SUM",
    "TABLE",
    "TO",
    "UNION",
    "UNIQUE",
    "UPDATE",
    "USER",
    "VALUES",
    "VIEW",
    "WHENEVER",
    "WHERE",
    "WITH",
    "WORK"
};

//------------------------------------------------------------------------------
// SQL data structs
//------------------------------------------------------------------------------
struct column
{
    char name[MAX_IDENTIFIER_LENGTH + 1U];
    int type;
    uintptr_t offset;
    size_t size;
};

struct table
{
    char name[MAX_IDENTIFIER_LENGTH + 1U];
    size_t num_columns;
    struct column* columns;
    size_t row_pitch;
    size_t num_rows;
    void* rows;
};

static size_t num_tables = 0U;
static struct table* tables = NULL;

//------------------------------------------------------------------------------
// SQL query parser
//------------------------------------------------------------------------------
#define NUMERIC_STORAGE_BUFFER_SIZE 16U

static int
parse_keyword(const char* token)
{
    if (NULL == token) return -1;
    unsigned int i;
    for (i = 0U; i < NUM_KEYWORDS; ++i)
    {
        if (0 == strcmp(token, key_words[i])) return i;
    }
    return -1;
}

static struct table*
get_table_by_name(const char* name)
{
    size_t i;
    for (i = 0U; i < num_tables; ++i)
    {
        if (0 == strcmp(tables[i].name, name)) return &tables[i];
    }
    return NULL;
}

//------------------------------------------------------------------------------
// Windows backend
//------------------------------------------------------------------------------
#ifdef CHRISSLY_SQL_WINDOWS
#undef UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"

struct client_connection
{
    SOCKET socket;
    HANDLE thread;
};
static struct client_connection connections[MAX_CONNECTIONS];

static SOCKET listen_socket = INVALID_SOCKET, connect_socket = INVALID_SOCKET;
static HANDLE listen_socket_thread = NULL, client_connection_lock = NULL, server_query_lock = NULL;

//------------------------- shutdown client connection -------------------------
static void
invalidate_connection(size_t client_index)
{
    WaitForSingleObject(client_connection_lock, INFINITE);
    closesocket(connections[client_index].socket);
    connections[client_index].socket = INVALID_SOCKET;
    CloseHandle(connections[client_index].thread);
    connections[client_index].thread = NULL;
    ReleaseMutex(client_connection_lock);
}

//---------------------------- client thread -----------------------------------
static DWORD WINAPI
client_socket_thread_proc(_In_ LPVOID lpParameter)
{
    size_t client_index = (size_t)lpParameter;
    int error = 0;
    char recv_buf[DEFAULT_BUFLEN];
    do
    {
        error = recv(connections[client_index].socket, recv_buf, DEFAULT_BUFLEN, 0);
        if (error > 0)
        {
            CHRISSLY_SQL_LOG("query received (%d bytes)\n", error);
            recv_buf[error < DEFAULT_BUFLEN ? error : DEFAULT_BUFLEN - 1U] = '\0';

            chrissly_sql_server_query(recv_buf, server_query_result_callback, (void*)client_index);

            // send query result back to the client
            int send_result = send(connections[client_index].socket, query_results[client_index], error, 0);
            if (SOCKET_ERROR == send_result)
            {
                CHRISSLY_SQL_LOG("send() failed with error: %d\n", WSAGetLastError());
                invalidate_connection(client_index);
                return CHRISSLY_SQL_ERR;
            }
            CHRISSLY_SQL_LOG("reply sent (%d bytes)\n", send_result);
        }
        else if (0 == error)
        {
            // client closed connection
            CHRISSLY_SQL_LOG("client %p closing connection...\n", (void*)connections[client_index].socket);
            invalidate_connection(client_index);
        }
        else
        {
            // error or shutdown
            int last_error = WSAGetLastError();
            if (last_error != WSAECONNABORTED)
            {
                CHRISSLY_SQL_LOG("recv() failed with error: %d\n", last_error);
                invalidate_connection(client_index);
            }
            return CHRISSLY_SQL_ERR;
        }
    } while (error > 0);

    return CHRISSLY_SQL_OK;
}

//----------------------------- listen thread ----------------------------------
static DWORD WINAPI
listen_socket_thread_proc(_In_ LPVOID lp_parameter)
{
    CHRISSLY_SQL_UNREFERENCED_PARAMETER(lp_parameter);
    SOCKET client_socket = INVALID_SOCKET;
    do
    {
        // accept a client socket
        client_socket = accept(listen_socket, NULL, NULL);
        if (INVALID_SOCKET == client_socket)
        {
            int error = WSAGetLastError();
            if (WSAEINTR == error)
            {
                CHRISSLY_SQL_LOG("server closed\n");
            }
            else
            {
                CHRISSLY_SQL_LOG("accept() failed with error: %d\n", error);
            }
            return CHRISSLY_SQL_ERR;
        }

        // search for free connection slot
        WaitForSingleObject(client_connection_lock, INFINITE);
        BOOL free_slot_found = FALSE;
        size_t i;
        for (i = 0U; i < MAX_CONNECTIONS; ++i)
        {
            if (INVALID_SOCKET == connections[i].socket)
            {
                connections[i].socket = client_socket;
                connections[i].thread = CreateThread(NULL, 0U, client_socket_thread_proc, (LPVOID)i, 0U, NULL);
                free_slot_found = TRUE;
                break;
            }
        }
        if (!free_slot_found)
        {
            shutdown(client_socket, SD_SEND);
            closesocket(client_socket);
        }
        ReleaseMutex(client_connection_lock);
    } while (client_socket != INVALID_SOCKET);

    return CHRISSLY_SQL_OK;
}
#endif // CHRISSLY_SQL_WINDOWS

//------------------------------------------------------------------------------
/**
*/
chrissly_sql_error
chrissly_sql_server_open(void)
{
    num_tables = 0U;
    tables = NULL;
    memset(query_results, 0, DEFAULT_BUFLEN * MAX_CONNECTIONS);

#ifdef CHRISSLY_SQL_WINDOWS
    client_connection_lock = CreateMutex(NULL, FALSE, NULL);

    unsigned int i;
    for (i = 0U; i < MAX_CONNECTIONS; ++i)
    {
        connections[i].socket = INVALID_SOCKET;
        connections[i].thread = NULL;
    }

    // initialize Winsock
    WSADATA wsa_data;
    int error = WSAStartup(MAKEWORD(2U, 2U), &wsa_data);
    if (error != 0)
    {
        CHRISSLY_SQL_LOG("WSAStartup() failed with error: %d\n", error);
        return CHRISSLY_SQL_ERR;
    }

    // resolve the server address and port
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo* result = NULL;
    error = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (error != 0)
    {
        CHRISSLY_SQL_LOG("getaddrinfo() failed with error: %d\n", error);
        WSACleanup();
        return CHRISSLY_SQL_ERR;
    }

    // create a SOCKET for the server to listen for client connections
    listen_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (INVALID_SOCKET == listen_socket)
    {
        CHRISSLY_SQL_LOG("socket() failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return CHRISSLY_SQL_ERR;
    }

    // setup the TCP listening socket
    error = bind(listen_socket, result->ai_addr, (int)result->ai_addrlen);
    if (SOCKET_ERROR == error)
    {
        CHRISSLY_SQL_LOG("bind() failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(listen_socket);
        listen_socket = INVALID_SOCKET;
        WSACleanup();
        return CHRISSLY_SQL_ERR;
    }

    freeaddrinfo(result);

    error = listen(listen_socket, SOMAXCONN);
    if (SOCKET_ERROR == error)
    {
        CHRISSLY_SQL_LOG("listen() failed with error: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        listen_socket = INVALID_SOCKET;
        WSACleanup();
        return CHRISSLY_SQL_ERR;
    }

    // create a thread that listens to incoming connections
    listen_socket_thread = CreateThread(NULL, 0U, listen_socket_thread_proc, NULL, 0U, NULL);

    server_query_lock = CreateMutex(NULL, FALSE, NULL);
#endif

    return CHRISSLY_SQL_OK;
}

//------------------------------------------------------------------------------
/**
*/
chrissly_sql_error
chrissly_sql_server_close(void)
{
    chrissly_sql_error retval = CHRISSLY_SQL_OK;

    // free all resources
    if (tables != NULL)
    {
        size_t t;
        for (t = 0U; t < num_tables; ++t)
        {
            free(tables[t].columns);
            free(tables[t].rows);
        }
        free(tables);
        num_tables = 0U;
        tables = NULL;
    }

#ifdef CHRISSLY_SQL_WINDOWS
    // terminate listen socket thread and socket api
    closesocket(listen_socket);
    listen_socket = INVALID_SOCKET;
    WaitForSingleObject(listen_socket_thread, INFINITE);
    CloseHandle(listen_socket_thread);
    listen_socket_thread = NULL;

    // terminate all client socket threads
    unsigned int i;
    for (i = 0U; i < MAX_CONNECTIONS; ++i)
    {
        HANDLE t = NULL;
        WaitForSingleObject(client_connection_lock, INFINITE);
        t = connections[i].thread;
        if (connections[i].socket != INVALID_SOCKET)
        {
            closesocket(connections[i].socket);
            connections[i].socket = INVALID_SOCKET;
            connections[i].thread = NULL;
        }
        ReleaseMutex(client_connection_lock);

        if (t != NULL)
        {
            WaitForSingleObject(t, INFINITE);
            CloseHandle(t);
        }
    }

    WSACleanup();
    CloseHandle(client_connection_lock);
    client_connection_lock = NULL;

    CloseHandle(server_query_lock);
    server_query_lock = NULL;
#endif

    return retval;
}

//------------------------------------------------------------------------------
/**
    ToDo:
      - replace strtok() with proper lexer, see chapter "5.3 <token>", for now
      every delimiter needs a leading and a trailing separator (space or tab)
      - check if tablename is upper case
      - check if table already exists
*/
chrissly_sql_error
chrissly_sql_server_query(char const* query, chrissly_sql_query_callback cb, void* user_data)
{
#ifdef CHRISSLY_SQL_WINDOWS
    WaitForSingleObject(server_query_lock, INFINITE);
#endif
    char* result_columns[16U] = {'\0'};
    char* result_values[16U] = {'\0'};
    size_t result_count = 0U, result_numeric_storage_count = 0U;
    char result_numeric_storage[16U][NUMERIC_STORAGE_BUFFER_SIZE] = {{'\0'}};

    struct table* new_table = NULL;
    size_t column_offset = 0U;

    char str[DEFAULT_BUFLEN] = {'\0'};
    (void)strcpy_s(str, DEFAULT_BUFLEN, query);
    char* context = NULL;
    char* token = strtok_s(str, SEPARATORS, &context);
    while (token != NULL)
    {
        if (KW_CREATE == parse_keyword(token))
        {
            token = strtok_s(NULL, SEPARATORS, &context);
            if (KW_TABLE == parse_keyword(token))
            {
                // create table
                char* table_name = strtok_s(NULL, SEPARATORS, &context);
                token = strtok_s(NULL, SEPARATORS, &context);
                if (0 != strcmp(token, "(")) return CHRISSLY_SQL_ERR;

                ++num_tables;
                struct table* table_alloc = realloc(tables, num_tables * sizeof(struct table));
                if (NULL == table_alloc) return CHRISSLY_SQL_ERR;
                tables = table_alloc;
                new_table = &tables[num_tables - 1U];
                memset(new_table, 0, sizeof(struct table));
                strncpy_s(new_table->name, MAX_IDENTIFIER_LENGTH + 1U, table_name, MAX_IDENTIFIER_LENGTH + 1U);
                column_offset = 0U;
                token = strtok_s(NULL, SEPARATORS, &context);
                while (token != NULL && 0 != strcmp(token, ")"))
                {
                    // create column
                    if (0 == strcmp(token, ",")) token = strtok_s(NULL, SEPARATORS, &context);
                    char* column_name = token;
                    ++new_table->num_columns;
                    struct column* column_alloc = realloc(new_table->columns, new_table->num_columns * sizeof(struct column));
                    if (NULL == column_alloc) return CHRISSLY_SQL_ERR;
                    new_table->columns = column_alloc;
                    struct column* new_column = &new_table->columns[new_table->num_columns - 1U];
                    strncpy_s(new_column->name, MAX_IDENTIFIER_LENGTH + 1U, column_name, MAX_IDENTIFIER_LENGTH + 1U);
                    new_column->offset = column_offset;
                    token = strtok_s(NULL, SEPARATORS, &context);
                    switch (parse_keyword(token))
                    {
                        case KW_INTEGER:
                        case KW_INT:
                            new_column->type = DT_INTEGER;
                            new_column->size = sizeof(int32_t);
                            column_offset += new_column->size;
                            new_table->row_pitch = column_offset;
                            break;
                        default:
                            new_column->type = -1;
                            new_column->size = 0U;
                            break;
                    }
                    result_columns[result_count] = column_name;
                    result_values[result_count] = "";
                    ++result_count;
                    token = strtok_s(NULL, SEPARATORS, &context);
                }
            }
            if (cb != NULL) cb(result_count, result_columns, result_values, user_data);
        }
        else if (KW_INSERT == parse_keyword(token))
        {
            token = strtok_s(NULL, SEPARATORS, &context);
            if (KW_INTO != parse_keyword(token)) return CHRISSLY_SQL_ERR;

            // insert into table
            token = strtok_s(NULL, SEPARATORS, &context);
            struct table* t = get_table_by_name(token);
            if (NULL == t) return CHRISSLY_SQL_ERR;

            token = strtok_s(NULL, SEPARATORS, &context);
            if (KW_VALUES != parse_keyword(token)) return CHRISSLY_SQL_ERR;

            token = strtok_s(NULL, SEPARATORS, &context);
            if (0 != strcmp(token, "(")) return CHRISSLY_SQL_ERR;

            ++t->num_rows;
            void* row_alloc = realloc(t->rows, t->num_rows * t->row_pitch);
            if (NULL == row_alloc) return CHRISSLY_SQL_ERR;
            t->rows = row_alloc;
            char* row = (char*)((uintptr_t)t->rows + (uintptr_t)(t->row_pitch * (t->num_rows - 1U)));
            size_t c;
            for (c = 0U; c < t->num_columns; ++c)
            {
                token = strtok_s(NULL, SEPARATORS, &context);
                if (0 == strcmp(token, ",")) token = strtok_s(NULL, SEPARATORS, &context);
                switch (t->columns[c].type)
                {
                    case DT_INTEGER:
                        {
                            int32_t number = atoi(token);
                            memcpy(row + t->columns[c].offset, &number, t->columns[c].size);
                            strcpy_s(result_numeric_storage[result_numeric_storage_count], NUMERIC_STORAGE_BUFFER_SIZE, token);
                            result_values[c] = result_numeric_storage[result_numeric_storage_count];
                            ++result_numeric_storage_count;
                        }
                        break;
                    default:
                        break;
                }
                result_columns[c] = t->columns[c].name;
            }
            result_count = t->num_columns;

            if (cb != NULL) cb(result_count, result_columns, result_values, user_data);
            result_numeric_storage_count = 0U;
        }
        else if (KW_SELECT == parse_keyword(token))
        {
            token = strtok_s(NULL, SEPARATORS, &context);
            if (0 == strcmp(token, "*"))
            {
                token = strtok_s(NULL, SEPARATORS, &context);
                if (KW_FROM != parse_keyword(token)) return CHRISSLY_SQL_ERR;

                // select all from table
                token = strtok_s(NULL, SEPARATORS, &context);
                struct table* t = get_table_by_name(token);
                if (NULL == t) return CHRISSLY_SQL_ERR;
                char* row = (char*)t->rows;
                result_count = t->num_columns;
                size_t r;
                for (r = 0U; r < t->num_rows; ++r)
                {
                    size_t c;
                    for (c = 0U; c < t->num_columns; ++c)
                    {
                        switch (t->columns[c].type)
                        {
                            case DT_INTEGER:
                                {
                                    int32_t number = 0U;
                                    memcpy(&number, row + t->columns[c].offset, t->columns[c].size);
                                    sprintf_s(result_numeric_storage[result_numeric_storage_count], NUMERIC_STORAGE_BUFFER_SIZE, "%i", number);
                                    result_values[c] = result_numeric_storage[result_numeric_storage_count];
                                    ++result_numeric_storage_count;
                                }
                                break;
                            default:
                                break;
                        }
                        result_columns[c] = t->columns[c].name;
                    }
                    if (cb != NULL) cb(result_count, result_columns, result_values, user_data);
                    row += t->row_pitch;
                }
            }
            result_numeric_storage_count = 0U;
        }
        token = strtok_s(NULL, SEPARATORS, &context);
    }
#ifdef CHRISSLY_SQL_WINDOWS
    ReleaseMutex(server_query_lock);
#endif
    return CHRISSLY_SQL_OK;
}

//------------------------------------------------------------------------------
/**
*/
chrissly_sql_error
chrissly_sql_client_connect(char const* ip_address)
{
#ifdef CHRISSLY_SQL_WINDOWS
    // initialize Winsock
    WSADATA wsa_data;
    int error = WSAStartup(MAKEWORD(2U, 2U), &wsa_data);
    if (error != 0)
    {
        CHRISSLY_SQL_LOG("WSAStartup() failed with error: %d\n", error);
        return CHRISSLY_SQL_ERR;
    }

    // resolve the server address and port
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = NULL;
    error = getaddrinfo(ip_address, DEFAULT_PORT, &hints, &result);
    if (error != 0)
    {
        CHRISSLY_SQL_LOG("getaddrinfo() failed with error: %d\n", error);
        WSACleanup();
        return CHRISSLY_SQL_ERR;
    }

    // attempt to connect to an address until one succeeds
    struct addrinfo* addr = NULL;
    for (addr = result; addr != NULL; addr = addr->ai_next)
    {
        // create a SOCKET for connecting to server
        connect_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (INVALID_SOCKET == connect_socket)
        {
            CHRISSLY_SQL_LOG("socket() failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return CHRISSLY_SQL_ERR;
        }

        // connect to server
        error = connect(connect_socket, addr->ai_addr, (int)addr->ai_addrlen);
        if (SOCKET_ERROR == error)
        {
            closesocket(connect_socket);
            connect_socket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (INVALID_SOCKET == connect_socket)
    {
        CHRISSLY_SQL_LOG("unable to connect to server!\n");
        WSACleanup();
        return CHRISSLY_SQL_ERR;
    }
#endif

    return CHRISSLY_SQL_OK;
}

//------------------------------------------------------------------------------
/**
*/
chrissly_sql_error
chrissly_sql_client_disconnect(void)
{
    chrissly_sql_error retval = CHRISSLY_SQL_OK;

#ifdef CHRISSLY_SQL_WINDOWS
    // shutdown the connection
    int error = shutdown(connect_socket, SD_SEND);
    if (SOCKET_ERROR == error)
    {
        CHRISSLY_SQL_LOG("shutdown() failed with error: %d\n", WSAGetLastError());
        retval = CHRISSLY_SQL_ERR;
    }

    // cleanup
    closesocket(connect_socket);
    connect_socket = INVALID_SOCKET;
    WSACleanup();
#endif

    return retval;
}

//------------------------------------------------------------------------------
/**
*/
chrissly_sql_error
chrissly_sql_client_query(char const* query, chrissly_sql_query_callback cb, void* user_data)
{
#ifdef CHRISSLY_SQL_WINDOWS
    // send an buffer
    int error = send(connect_socket, query, (int)strlen(query), 0);
    if (SOCKET_ERROR == error)
    {
        int last_error = WSAGetLastError();
        if (WSAECONNRESET == last_error)
        {
            CHRISSLY_SQL_LOG("server closing connection...\n");
        }
        else
        {
            CHRISSLY_SQL_LOG("send() failed with error: %d\n", last_error);
        }
        return CHRISSLY_SQL_ERR;
    }
    CHRISSLY_SQL_LOG("query sent (%d bytes)\n", error);

    // receive reply
    char recv_buf[DEFAULT_BUFLEN];
    error = recv(connect_socket, recv_buf, DEFAULT_BUFLEN, 0);
    if (error > 0)
    {
        CHRISSLY_SQL_LOG("reply received (%d bytes)\n", error);
        recv_buf[error < DEFAULT_BUFLEN ? error : DEFAULT_BUFLEN - 1U] = '\0';
        if (cb != NULL)
        {
            char* columns[1U] = {recv_buf};
            char* values[1U] = {""};
            cb(1U, columns, values, user_data);
        }
    }
    else if (0 == error)
    {
        CHRISSLY_SQL_LOG("closing connection...\n");
    }
    else
    {
        CHRISSLY_SQL_LOG("recv() failed with error: %d\n", WSAGetLastError());
    }
#endif

    return CHRISSLY_SQL_OK;
}

#endif
