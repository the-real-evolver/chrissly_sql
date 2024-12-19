//------------------------------------------------------------------------------
/**
    chrissly_sql.h

    A single-header file library that implements a minimal sql server
    and client.

    Add this line:
        #define CHRISSLY_SQL_IMPLEMENTATION
    before you include this file in *one* C or C++ file to create the implementation.

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

typedef void(*chrissly_sql_query_callback)(unsigned int, char**, char**, void*);

// initialise server and listen for client connections
chrissly_sql_error chrissly_sql_server_open(void);
// close connections to clients
chrissly_sql_error chrissly_sql_server_close(void);
chrissly_sql_error chrissly_sql_server_create_db(char const* file_name);
chrissly_sql_error chrissly_sql_server_load_db(char const* file_name);
chrissly_sql_error chrissly_sql_server_save_db(void);
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
#include <stdarg.h>
#include <string.h>

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
server_query_result_callback(unsigned int count, char** columns, char** values, void* user_data)
{
    CHRISSLY_SQL_UNREFERENCED_PARAMETER(columns);
    CHRISSLY_SQL_UNREFERENCED_PARAMETER(count);
    (void)strcpy_s(query_results[(uintptr_t)user_data], DEFAULT_BUFLEN, values[0U]);
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
static HANDLE listen_socket_thread = NULL, client_connection_lock = NULL;

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
// client thread
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

//------------------------------------------------------------------------------
// listen thread
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
#endif

    return retval;
}

//------------------------------------------------------------------------------
/**
*/
chrissly_sql_error
chrissly_sql_server_query(char const* query, chrissly_sql_query_callback cb, void* user_data)
{
    if (cb != NULL)
    {
        char* columns[1U] = {"DUMMY_COLUMN"};
        char* values[1U] = {(char*)query};
        cb(1U, columns, values, user_data);
    }

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
            char* columns[1U] = {"DUMMY_COLUMN"};
            char* values[1U] = {recv_buf};
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
