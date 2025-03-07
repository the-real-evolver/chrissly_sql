//------------------------------------------------------------------------------
//  server.c
//  (C) 2024 Christian Bleicher
//------------------------------------------------------------------------------
#include <stdio.h>
#include <conio.h>
#define CHRISSLY_SQL_WINDOWS
#define CHRISSLY_SQL_IMPLEMENTATION
#include "chrissly_sql.h"

//------------------------------------------------------------------------------
/**
*/
static void
query_result_callback(size_t column_count, char** columns, size_t row_count, char** values, void* user_data)
{
    CHRISSLY_SQL_UNREFERENCED_PARAMETER(user_data);
    size_t c, r;
    for (c = 0U; c < column_count; ++c)
    {
        printf("%-16s", columns[c]);
    }
    printf("\n");
    for (r = 0U; r < row_count; ++r)
    {
        for (c = 0U; c < column_count; ++c)
        {
            printf("%-16s", values[r * column_count + c]);
        }
        printf("\n");
    }
    printf("\n");
}

//------------------------------------------------------------------------------
/**
*/
int
main()
{
    printf("Hello ChrisslySQL-Server!\n");
    chrissly_sql_server_open();
    printf("Press any key to quit\n");
    (void)_getch();
    chrissly_sql_server_close();
}