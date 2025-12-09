//------------------------------------------------------------------------------
//  client.c
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
main(void)
{
    printf("Hello ChrisslySQL-Client!\n");
    chrissly_sql_client_connect("localhost");
    chrissly_sql_client_query("CREATE TABLE A_TABLE_NAME (A_COLUMN_NAME INTEGER, SECOND_COLUMN INT, THIRD_COLUMN INT);", query_result_callback, NULL);
    chrissly_sql_client_query("INSERT INTO A_TABLE_NAME VALUES (123, 456, 789);", query_result_callback, NULL);
    chrissly_sql_client_query("SELECT * FROM A_TABLE_NAME;", query_result_callback, NULL);
    (void)_getch();
    chrissly_sql_client_disconnect();
    return 0;
}