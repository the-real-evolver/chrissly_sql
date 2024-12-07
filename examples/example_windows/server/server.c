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
int
main()
{
    printf("Hello ChrisslySQL-Server!\n");
    chrissly_sql_server_open();
    printf("Press any key to quit\n");
    (void)_getch();
    chrissly_sql_server_close();
}