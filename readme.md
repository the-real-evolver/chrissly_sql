# Chrissly SQL (WIP)
   A single-header file library that implements a minimal sql server and client. Aims for SQL-86 standard.
## Motivation
## Usage
### Server
```c
#include <stdio.h>
#include <conio.h>
#define CHRISSLY_SQL_WINDOWS
#define CHRISSLY_SQL_IMPLEMENTATION
#include "chrissly_sql.h"

int
main()
{
    printf("Hello ChrisslySQL-Server!\n");
    chrissly_sql_server_open();
    printf("Press any key to quit\n");
    (void)_getch();
    chrissly_sql_server_close();
}
```
### Client
```c
#include <stdio.h>
#define CHRISSLY_SQL_WINDOWS
#define CHRISSLY_SQL_IMPLEMENTATION
#include "chrissly_sql.h"

static void
query_result_callback(unsigned int count, char** columns, char** values, void* user_data)
{
    unsigned int i;
    for (i = 0U; i < count; ++i)
    {
        printf("--> query result column: %s value: %s\n", columns[i], values[i]);
    }
}

int
main()
{
    printf("Hello ChrisslySQL-Client!\n");
    chrissly_sql_client_connect("localhost");
    chrissly_sql_client_query("SELECT * FROM MYTABLE1", query_result_callback, NULL);
    (void)_getch();
    chrissly_sql_client_disconnect();
}
```
### Status
- network implementation on windows done (multiple clients can connect to the server)