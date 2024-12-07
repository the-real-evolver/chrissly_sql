//------------------------------------------------------------------------------
//  client.c
//  (C) 2024 Christian Bleicher
//------------------------------------------------------------------------------
#include <stdio.h>
#define CHRISSLY_SQL_WINDOWS
#define CHRISSLY_SQL_IMPLEMENTATION
#include "chrissly_sql.h"

//------------------------------------------------------------------------------
/**
*/
static void
query_result_callback(unsigned int count, char** columns, char** values, void* user_data)
{
    unsigned int i;
    for (i = 0U; i < count; ++i)
    {
        printf("--> query result column: %s value: %s\n", columns[i], values[i]);
    }
}

//------------------------------------------------------------------------------
/**
*/
int
main()
{
    printf("Hello ChrisslySQL-Client!\n");
    chrissly_sql_client_connect("localhost");
    chrissly_sql_client_query("SELECT * FROM MYTABLE1", query_result_callback, NULL);
    (void)_getch();
    chrissly_sql_client_disconnect();
}