/*-*-c-*- ************************************************************
* Copyright (C) 2001-2005,  Simon Kagstrom
* Created by Danny Li-on 11/04/2018
*
* Filename:      test.c
* Description:   Test libghthash
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Library General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU Library General Public
* License along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
* 02111-1307, USA.
*
********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ght_hash_table.h"

void * test_ght_malloc(unsigned __int64 size)
{
	return malloc(size);
}

void test_ght_free(void *ptr)
{
	free(ptr);
}

void test_Simple(void)
{
	ght_hash_table_t *p_table;
	int *p_data;
	int *p_he;

	p_table = ght_create(128, &test_ght_malloc, &test_ght_free, NULL);
	if (NULL == p_table)
	{
		// We can't allocate the hash-table, nothing to do here
		return;
	}

	p_data = (int*)malloc(sizeof(int));
	if (NULL == p_data)
	{
		// We can't allocate the data, nothing to do here
		return;
	}

	/* Assign the data a value */
	*p_data = 15;

	/* Insert "blabla" into the hash table */
	assert(0 == ght_insert(
		p_table,
		p_data,
		(unsigned int)(sizeof(char)*strlen("blabla")),
		"blabla"));

	/* Search for "blabla" */
	p_he = ght_get(
		p_table,
		(unsigned int)(sizeof(char)*strlen("blabla")),
		"blabla");
	assert(NULL != p_he);

	/* Remove the hash table */
	ght_finalize(p_table);
}

void TEST_RunTests(void)
{
	test_Simple();
}

int main(int argc, char *argv[])
{
	TEST_RunTests();
	printf("libghthash tests passed!");
	return 0;
}