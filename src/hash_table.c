/*********************************************************************
 *
 * Copyright (C) 2001-2005,  Simon Kagstrom
 * Edited by Danny Li-on 11/04/2018
 *
 * Filename:      hash_table.c
 * Description:   The implementation of the hash table (MK2).
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
 * $Id: hash_table.c 15761 2007-07-15 06:08:52Z ska $
 *
 ********************************************************************/

#include "ght_hash_table.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x)   (x)
#endif

#ifndef NULL
#define NULL 0
#endif

// We define these intrinsic functions ourselves to so we can remove the 
// standard library dependency
static int __cdecl memcmp(const void *s1,
	const void *s2,
	unsigned __int64 n);

static void * __cdecl memcpy(
	void* pvDst,
	void const* pvSrc,
	unsigned __int64 cbSize);

static void * __cdecl memset(
	void* pvDst,
	int iValue,
	unsigned __int64 cbSize);

#pragma function(memcmp)
#pragma function(memcpy)
#pragma function(memset)

static int __cdecl memcmp(const void *s1,
	const void *s2,
	unsigned __int64 n)
{
	const unsigned char *p1 = s1;
	const unsigned char *p2 = s2;
	while (n--)
	{
		if (*p1 != *p2)
		{
			return *p1 - *p2;
		}
		else
		{
			p1++, p2++;
		}
	}
	return 0;
}

static void * __cdecl memcpy(void* pvDst,
	void const* pvSrc,
	unsigned __int64 cbSize)
{
	unsigned char *pcSrc = NULL;
	unsigned char *pcDst = NULL;
	unsigned __int64 *pqwSrc = (unsigned __int64 *)pvSrc;
	unsigned __int64 *pqwDst = (unsigned __int64 *)pvDst;
	unsigned __int64 i;

	if ((NULL == pvDst)
		|| (NULL == pvSrc)
		|| (0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	// Copy bytes in unsigned __int64 increments to make things a bit faster
	for (i = 0; i < (cbSize / sizeof(unsigned __int64 )); i++)
	{
		pqwDst[i] = pqwSrc[i];
	}

	// Copy the remaining bytes as regular chars
	pcSrc = (unsigned char *)((unsigned __int64 )pvSrc + i * sizeof(unsigned __int64 ));
	pcDst = (unsigned char *)((unsigned __int64 )pvDst + i * sizeof(unsigned __int64 ));
	for (i = 0; i < (cbSize % sizeof(unsigned __int64 )); i++)
	{
		pcDst[i] = pcSrc[i];
	}

	return pvDst;
}

static void * __cdecl memset(void* pvDst,
	int iValue,
	unsigned __int64 cbSize)
{
	unsigned char ucValue = (unsigned char)iValue;
	unsigned char *pucDst = NULL;
	unsigned __int64 *pqwDst = (unsigned __int64 *)pvDst;
	unsigned __int64 qwValue = 0;
	unsigned char *pucValue = (unsigned char *)&qwValue;
	unsigned __int64 i = 0;

	if ((NULL == pvDst)
		|| (0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	// Build a unsigned __int64 with all bytes set to ucValue
	for (i = 0; i < sizeof(qwValue); i++)
	{
		pucValue[i] = ucValue;
	}

	// Set bytes in unsigned __int64 increments to make things a bit faster
	for (i = 0; i < (cbSize / sizeof(unsigned __int64 )); i++)
	{
		pqwDst[i] = qwValue;
	}

	// Set the remaining bytes as regular chars
	pucDst = (unsigned char *)((unsigned __int64 )pvDst + i * sizeof(unsigned __int64 ));
	for (i = 0; i < (cbSize % sizeof(unsigned __int64 )); i++)
	{
		pucDst[i] = ucValue;
	}

	return pvDst;
}

 /* Prototypes */
static void transpose(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_entry_t *p_entry);

static void move_to_front(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_entry_t *p_entry);

static void free_entry_chain(ght_hash_table_t *p_ht,
	ght_hash_entry_t *p_entry);

static ght_hash_entry_t *search_in_bucket(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_key_t *p_key,
	unsigned char i_heuristics);

static void hk_fill(ght_hash_key_t *p_hk,
	int i_size,
	const void *p_key);

static ght_hash_entry_t *he_create(ght_hash_table_t *p_ht,
	void *p_data,
	unsigned int i_key_size,
	const void *p_key_data);

static void he_finalize(ght_hash_table_t *p_ht,
	ght_hash_entry_t *p_he);

/* --- private methods --- */

/* Move p_entry one up in its list. */
static void transpose(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_entry_t *p_entry)
{
	/*
	 *  __    __    __    __
	 * |A_|->|X_|->|Y_|->|B_|
	 *             /
	 * =>        p_entry
	 *  __    __/   __    __
	 * |A_|->|Y_|->|X_|->|B_|
	 */
	if (p_entry->p_prev) /* Otherwise p_entry is already first. */
	{
		ght_hash_entry_t *p_x = p_entry->p_prev;
		ght_hash_entry_t *p_a = p_x ? p_x->p_prev : NULL;
		ght_hash_entry_t *p_b = p_entry->p_next;

		if (p_a)
		{
			p_a->p_next = p_entry;
		}
		else /* This element is now placed first */
		{
			p_ht->pp_entries[l_bucket] = p_entry;
		}

		if (p_b)
		{
			p_b->p_prev = p_x;
		}
		if (p_x)
		{
			p_x->p_next = p_entry->p_next;
			p_x->p_prev = p_entry;
		}
		p_entry->p_next = p_x;
		p_entry->p_prev = p_a;
	}
}

/* Move p_entry first */
static void move_to_front(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_entry_t *p_entry)
{
	/*
	 *  __    __    __
	 * |A_|->|B_|->|X_|
	 *            /
	 * =>  p_entry
	 *  __/   __    __
	 * |X_|->|A_|->|B_|
	 */
	if (p_entry == p_ht->pp_entries[l_bucket])
	{
		return;
	}

	/* Link p_entry out of the list. */
	p_entry->p_prev->p_next = p_entry->p_next;
	if (p_entry->p_next)
	{
		p_entry->p_next->p_prev = p_entry->p_prev;
	}

	/* Place p_entry first */
	p_entry->p_next = p_ht->pp_entries[l_bucket];
	p_entry->p_prev = NULL;
	p_ht->pp_entries[l_bucket]->p_prev = p_entry;
	p_ht->pp_entries[l_bucket] = p_entry;
}

static void remove_from_chain(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_entry_t *p)
{
	if (p->p_prev)
	{
		p->p_prev->p_next = p->p_next;
	}
	else /* first in list */
	{
		p_ht->pp_entries[l_bucket] = p->p_next;
	}
	if (p->p_next)
	{
		p->p_next->p_prev = p->p_prev;
	}

	if (p->p_older)
	{
		p->p_older->p_newer = p->p_newer;
	}
	else /* oldest */
	{
		p_ht->p_oldest = p->p_newer;
	}
	if (p->p_newer)
	{
		p->p_newer->p_older = p->p_older;
	}
	else /* newest */
	{
		p_ht->p_newest = p->p_older;
	}
}

/* Search for an element in a bucket */
static ght_hash_entry_t *search_in_bucket(ght_hash_table_t *p_ht,
	ght_uint32_t l_bucket,
	ght_hash_key_t *p_key,
	unsigned char i_heuristics)
{
	ght_hash_entry_t *p_e;

	for (p_e = p_ht->pp_entries[l_bucket];
		p_e;
		p_e = p_e->p_next)
	{
		if ((p_e->key.i_size == p_key->i_size) &&
			(memcmp(p_e->key.p_key, p_key->p_key, p_e->key.i_size) == 0))
		{
			/* Matching entry found - Apply heuristics, if any */
			switch (i_heuristics)
			{
			case GHT_HEURISTICS_MOVE_TO_FRONT:
				move_to_front(p_ht, l_bucket, p_e);
				break;
			case GHT_HEURISTICS_TRANSPOSE:
				transpose(p_ht, l_bucket, p_e);
				break;
			default:
				break;
			}
			return p_e;
		}
	}
	return NULL;
}

/* Free a chain of entries (in a bucket) */
static void free_entry_chain(ght_hash_table_t *p_ht, ght_hash_entry_t *p_entry)
{
	ght_hash_entry_t *p_e = p_entry;

	while (p_e)
	{
		ght_hash_entry_t *p_e_next = p_e->p_next;
		he_finalize(p_ht, p_e);
		p_e = p_e_next;
	}
}


/* Fill in the data to a existing hash key */
static void hk_fill(ght_hash_key_t *p_hk, int i_size, const void *p_key)
{
	p_hk->i_size = i_size;
	p_hk->p_key = p_key;
}

/* Create an hash entry */
static ght_hash_entry_t *he_create(ght_hash_table_t *p_ht, void *p_data,
	unsigned int i_key_size, const void *p_key_data)
{
	ght_hash_entry_t *p_he;

	/*
	 * An element like the following is allocated:
	 *        elem->p_key
	 *       /   elem->p_key->p_key_data
	 *  ____|___/________
	 * |elem|key|key data|
	 * |____|___|________|
	 *
	 * That is, the key and the key data is stored "inline" within the
	 * hash entry.
	 *
	 * This saves space since fn_alloc only is called once and thus avoids
	 * some fragmentation. Thanks to Dru Lemley for this idea.
	 */
	p_he = (ght_hash_entry_t*)p_ht->fn_alloc(sizeof(ght_hash_entry_t) + i_key_size);
	if (!(p_he))
	{
		// LOG_ERROR("fn_alloc failed!\n");
		return NULL;
	}

	p_he->p_data = p_data;
	p_he->p_next = NULL;
	p_he->p_prev = NULL;
	p_he->p_older = NULL;
	p_he->p_newer = NULL;

	/* Create the key */
	p_he->key.i_size = i_key_size;
	memcpy(p_he + 1, p_key_data, i_key_size);
	p_he->key.p_key = (void*)(p_he + 1);

	return p_he;
}

/* Finalize (fn_free) a hash entry */
static void he_finalize(ght_hash_table_t *p_ht, ght_hash_entry_t *p_he)
{
	p_he->p_next = NULL;
	p_he->p_prev = NULL;
	p_he->p_older = NULL;
	p_he->p_newer = NULL;

	/* Free the entry */
	p_ht->fn_free(p_he);
}

#if 0
/* Tried this to avoid recalculating hash values by caching
 * them. Overhead larger than benefits.
 */
static ght_uint32_t get_hash_value(ght_hash_table_t *p_ht, ght_hash_key_t *p_key)
{
	int i;

	if (p_key->i_size > sizeof(uint64_t))
		return p_ht->fn_hash(p_key);

	/* Lookup in the hash value cache */
	for (i = 0; i < GHT_N_CACHED_HASH_KEYS; i++)
	{
		if (p_key->i_size == p_ht->cached_keys[i].key.i_size &&
			memcmp(p_key->p_key, p_ht->cached_keys[i].key.p_key, p_key->i_size) == 0)
			return p_ht->cached_keys[i].hash_val;
	}
	p_ht->cur_cache_evict = (p_ht->cur_cache_evict + 1) % GHT_N_CACHED_HASH_KEYS;
	p_ht->cached_keys[p_ht->cur_cache_evict].key = *p_key;
	p_ht->cached_keys[p_ht->cur_cache_evict].hash_val = p_ht->fn_hash(p_key);

	return p_ht->cached_keys[p_ht->cur_cache_evict].hash_val;
}
#else
# define get_hash_value(p_ht, p_key) ( (p_ht)->fn_hash(p_key) )
#endif


/* --- Exported methods --- */
/* Create a new hash table */
ght_hash_table_t *ght_create(unsigned int i_size,
	ght_fn_alloc_t fn_alloc,
	ght_fn_free_t fn_free,
	ght_fn_hash_t fn_hash)
{
	ght_hash_table_t *p_ht;
	int i = 1;

	if (	(0 == i_size)
		||	(NULL == fn_alloc)
		||	(NULL == fn_free))
	{
		return NULL;
	}

	p_ht = (ght_hash_table_t*)fn_alloc(sizeof(ght_hash_table_t));
	if (NULL == p_ht)
	{
		return NULL;
	}

	/* Set the size of the hash table to the nearest 2^i higher then i_size */
	p_ht->i_size = 1;
	while (p_ht->i_size < i_size)
	{
		p_ht->i_size = 1 << i++;
	}

	p_ht->i_size_mask = (1 << (i - 1)) - 1; /* Mask to & with */
	p_ht->i_items = 0;

	/* Standard values for allocations */
	p_ht->fn_alloc = fn_alloc;
	p_ht->fn_free = fn_free;
	p_ht->fn_hash = (NULL != fn_hash) ? fn_hash : ght_one_at_a_time_hash;

	/* Set flags */
	p_ht->i_heuristics = GHT_HEURISTICS_NONE;
	p_ht->i_automatic_rehash = FALSE;

	p_ht->bucket_limit = 0;
	p_ht->fn_bucket_free = NULL;

	/* Create an empty bucket list. */
	p_ht->pp_entries = (ght_hash_entry_t**)fn_alloc( \
		p_ht->i_size * sizeof(ght_hash_entry_t*));
	if (!(p_ht->pp_entries))
	{
		// LOG_ERROR("fn_alloc");
		p_ht->fn_free(p_ht);
		return NULL;
	}
	memset(p_ht->pp_entries, 0, p_ht->i_size * sizeof(ght_hash_entry_t*));

	/* Initialize the number of entries in each bucket to zero */
	p_ht->p_nr = (unsigned int*)fn_alloc(p_ht->i_size * sizeof(int));
	if (!(p_ht->p_nr))
	{
		// LOG_ERROR("fn_alloc");
		p_ht->fn_free(p_ht->pp_entries);
		p_ht->fn_free(p_ht);
		return NULL;
	}
	memset(p_ht->p_nr, 0, p_ht->i_size * sizeof(int));

	p_ht->p_oldest = NULL;
	p_ht->p_newest = NULL;

	return p_ht;
}

/* Set the allocation/deallocation function to use */
void ght_set_alloc(ght_hash_table_t *p_ht,
	ght_fn_alloc_t fn_alloc,
	ght_fn_free_t fn_free)
{
	if (	(NULL == p_ht)
		||	(NULL == fn_alloc)
		||	(NULL == fn_free))
	{
		return;
	}
	p_ht->fn_alloc = fn_alloc;
	p_ht->fn_free = fn_free;
}

/* Set the hash function to use */
void ght_set_hash(ght_hash_table_t *p_ht, ght_fn_hash_t fn_hash)
{
	if (	(NULL == p_ht)
		||	(NULL == fn_hash))
	{
		return;
	}
	p_ht->fn_hash = fn_hash;
}

/* Set the heuristics to use. */
void ght_set_heuristics(ght_hash_table_t *p_ht, int i_heuristics)
{
	if (NULL == p_ht)
	{
		return;
	}
	p_ht->i_heuristics = i_heuristics;
}

/* Set the rehashing status of the table. */
void ght_set_rehash(ght_hash_table_t *p_ht, int b_rehash)
{
	if (NULL == p_ht)
	{
		return;
	}
	p_ht->i_automatic_rehash = b_rehash;
}

void ght_set_bounded_buckets(ght_hash_table_t *p_ht,
	unsigned int limit,
	ght_fn_bucket_free_callback_t fn)
{
	if (	(NULL == p_ht)
		||	(limit > 0 && fn == NULL))
	{
		return;
	}

	p_ht->bucket_limit = limit;
	p_ht->fn_bucket_free = fn;
}


/* Get the number of items in the hash table */
unsigned int ght_size(ght_hash_table_t *p_ht)
{
	if (NULL == p_ht)
	{
		return 0;
	}
	return p_ht->i_items;
}

/* Get the size of the hash table */
unsigned int ght_table_size(ght_hash_table_t *p_ht)
{
	if (NULL == p_ht)
	{
		return 0;
	}
	return p_ht->i_size;
}

/* Insert an entry into the hash table */
int ght_insert(ght_hash_table_t *p_ht,
	void *p_entry_data,
	unsigned int i_key_size,
	const void *p_key_data)
{
	ght_hash_entry_t *p_entry = NULL;
	ght_uint32_t l_key = 0;
	ght_hash_key_t key = { 0 };

	if (	(NULL == p_ht)
		||	(0 == i_key_size)
		||	(NULL == p_key_data))
	{
		return -2;
	}

	hk_fill(&key, i_key_size, p_key_data);
	l_key = get_hash_value(p_ht, &key) & p_ht->i_size_mask;
	if (search_in_bucket(p_ht, l_key, &key, 0))
	{
		/* Don't insert if the key is already present. */
		return -1;
	}
	p_entry = he_create(p_ht, p_entry_data, i_key_size, p_key_data);
	if (!(p_entry))
	{
		return -2;
	}

	/* Rehash if the number of items inserted is too high. */
	if (p_ht->i_automatic_rehash && p_ht->i_items > 2 * p_ht->i_size)
	{
		ght_rehash(p_ht, 2 * p_ht->i_size);
		/* Recalculate l_key after ght_rehash has updated i_size_mask */
		l_key = get_hash_value(p_ht, &key) & p_ht->i_size_mask;
	}

	/* Place the entry first in the list. */
	p_entry->p_next = p_ht->pp_entries[l_key];
	p_entry->p_prev = NULL;
	if (p_ht->pp_entries[l_key])
	{
		p_ht->pp_entries[l_key]->p_prev = p_entry;
	}
	p_ht->pp_entries[l_key] = p_entry;

	/* If this is a limited bucket hash table, potentially remove the last item */
	if (p_ht->bucket_limit != 0 &&
		p_ht->p_nr[l_key] >= p_ht->bucket_limit)
	{
		ght_hash_entry_t *p = NULL;

		/* Loop through entries until the last
		 *
		 * FIXME: Better with a pointer to the last entry
		 */
		for (p = p_ht->pp_entries[l_key];
			p->p_next != NULL;
			p = p->p_next);

		// DEBUG_ASSERT(p && p->p_next == NULL);

		/* To allow it to be reinserted in fn_bucket_free */
		remove_from_chain(p_ht, l_key, p);
		p_ht->fn_bucket_free(p->p_data, p->key.p_key);

		he_finalize(p_ht, p);
	}
	else
	{
		p_ht->p_nr[l_key]++;

		// DEBUG_ASSERT( p_ht->pp_entries[l_key]?p_ht->pp_entries[l_key]->p_prev == NULL:1 );

		p_ht->i_items++;
	}

	if (p_ht->p_oldest == NULL)
	{
		p_ht->p_oldest = p_entry;
	}
	p_entry->p_older = p_ht->p_newest;

	if (p_ht->p_newest != NULL)
	{
		p_ht->p_newest->p_newer = p_entry;
	}

	p_ht->p_newest = p_entry;

	return 0;
}

/* Get an entry from the hash table. The entry is returned, or NULL if it wasn't found */
void *ght_get(ght_hash_table_t *p_ht,
	unsigned int i_key_size,
	const void *p_key_data)
{
	ght_hash_entry_t *p_e = NULL;
	ght_hash_key_t key = { 0 };
	ght_uint32_t l_key = 0;

	if (	(NULL == p_ht)
		||	(0 == i_key_size)
		||	(NULL == p_key_data))
	{
		return NULL;
	}

	hk_fill(&key, i_key_size, p_key_data);

	l_key = get_hash_value(p_ht, &key) & p_ht->i_size_mask;

	/* Check that the first element in the list really is the first. */
	// DEBUG_ASSERT( p_ht->pp_entries[l_key]?p_ht->pp_entries[l_key]->p_prev == NULL:1 );

	/* LOCK: p_ht->pp_entries[l_key] */
	p_e = search_in_bucket(p_ht, l_key, &key, (unsigned char)p_ht->i_heuristics);
	/* UNLOCK: p_ht->pp_entries[l_key] */

	return (p_e ? p_e->p_data : NULL);
}

/* Replace an entry from the hash table. The entry is returned,
   or NULL if it wasn't found */
void *ght_replace(ght_hash_table_t *p_ht,
	void *p_entry_data,
	unsigned int i_key_size,
	const void *p_key_data)
{
	ght_hash_entry_t *p_e = NULL;
	ght_hash_key_t key = { 0 };
	ght_uint32_t l_key = 0;
	void *p_old = NULL;

	if (	(NULL == p_ht)
		||	(0 == i_key_size)
		||	(NULL == p_key_data))
	{
		return NULL;
	}

	hk_fill(&key, i_key_size, p_key_data);

	l_key = get_hash_value(p_ht, &key) & p_ht->i_size_mask;

	/* Check that the first element in the list really is the first. */
	// DEBUG_ASSERT( p_ht->pp_entries[l_key]?p_ht->pp_entries[l_key]->p_prev == NULL:1 );

	/* LOCK: p_ht->pp_entries[l_key] */
	p_e = search_in_bucket(p_ht, l_key, &key, (unsigned char)p_ht->i_heuristics);
	/* UNLOCK: p_ht->pp_entries[l_key] */

	if (!p_e)
		return NULL;

	p_old = p_e->p_data;
	p_e->p_data = p_entry_data;

	return p_old;
}

/* Remove an entry from the hash table. The removed entry, or NULL, is
   returned (and NOT free). */
void *ght_remove(ght_hash_table_t *p_ht,
	unsigned int i_key_size,
	const void *p_key_data)
{
	ght_hash_entry_t *p_out = NULL;
	ght_hash_key_t key = { 0 };
	ght_uint32_t l_key = 0;
	void *p_ret = NULL;

	if (	(NULL == p_ht)
		||	(0 == i_key_size)
		||	(NULL == p_key_data))
	{
		return NULL;
	}

	hk_fill(&key, i_key_size, p_key_data);
	l_key = get_hash_value(p_ht, &key) & p_ht->i_size_mask;

	/* Check that the first element really is the first */
	// DEBUG_ASSERT( (p_ht->pp_entries[l_key]?p_ht->pp_entries[l_key]->p_prev == NULL:1) );

	/* LOCK: p_ht->pp_entries[l_key] */
	p_out = search_in_bucket(p_ht, l_key, &key, 0);

	/* Link p_out out of the list. */
	if (p_out)
	{
		remove_from_chain(p_ht, l_key, p_out);

		/* This should ONLY be done for normal items (for now all items) */
		p_ht->i_items--;

		p_ht->p_nr[l_key]--;
		/* UNLOCK: p_ht->pp_entries[l_key] */
		p_out->p_next = NULL;
		p_out->p_prev = NULL;

		p_ret = p_out->p_data;
		he_finalize(p_ht, p_out);
	}
	/* else: UNLOCK: p_ht->pp_entries[l_key] */

	return p_ret;
}

static void *first_keysize(ght_hash_table_t *p_ht, ght_iterator_t *p_iterator, const void **pp_key, unsigned int *size)
{
	/* Fill the iterator */
	p_iterator->p_entry = p_ht->p_oldest;

	if (p_iterator->p_entry)
	{
		p_iterator->p_next = p_iterator->p_entry->p_newer;
		*pp_key = p_iterator->p_entry->key.p_key;
		if (size != NULL)
			*size = p_iterator->p_entry->key.i_size;

		return p_iterator->p_entry->p_data;
	}

	p_iterator->p_next = NULL;
	*pp_key = NULL;
	if (size != NULL)
		*size = 0;

	return NULL;
}



/* Get the first entry in an iteration */
void *ght_first(ght_hash_table_t *p_ht,
	ght_iterator_t *p_iterator,
	const void **pp_key)
{
	if (	(NULL == p_ht)
		||	(NULL == p_iterator)
		||	(NULL == pp_key))
	{
		return NULL;
	}
	return first_keysize(p_ht, p_iterator, pp_key, NULL);
}

void *ght_first_keysize(ght_hash_table_t *p_ht,
	ght_iterator_t *p_iterator,
	const void **pp_key,
	unsigned int *size)
{
	if (	(NULL == p_ht)
		||	(NULL == p_iterator)
		||	(NULL == pp_key)
		||	(NULL == size))
	{
		return NULL;
	}
	return first_keysize(p_ht, p_iterator, pp_key, size);
}


static void *next_keysize(ght_hash_table_t *p_ht,
	ght_iterator_t *p_iterator,
	const void **pp_key,
	unsigned int *size)
{
	UNREFERENCED_PARAMETER(p_ht);
	
	if (p_iterator->p_next)
	{
		/* More entries */
		p_iterator->p_entry = p_iterator->p_next;
		p_iterator->p_next = p_iterator->p_next->p_newer;

		*pp_key = p_iterator->p_entry->key.p_key;
		if (size != NULL)
			*size = p_iterator->p_entry->key.i_size;

		return p_iterator->p_entry->p_data; /* We know that this is non-NULL */
	}

	/* Last entry */
	p_iterator->p_entry = NULL;
	p_iterator->p_next = NULL;

	*pp_key = NULL;
	if (size != NULL)
		*size = 0;

	return NULL;
}


/* Get the next entry in an iteration. You have to call ght_first
   once initially before you use this function */
void *ght_next(ght_hash_table_t *p_ht,
	ght_iterator_t *p_iterator,
	const void **pp_key)
{
	if (	(NULL == p_ht)
		||	(NULL == p_iterator)
		||	(NULL == pp_key))
	{
		return NULL;
	}
	return next_keysize(p_ht, p_iterator, pp_key, NULL);
}

void *ght_next_keysize(ght_hash_table_t *p_ht,
	ght_iterator_t *p_iterator,
	const void **pp_key,
	unsigned int *size)
{
	if (	(NULL == p_ht)
		||	(NULL == p_iterator)
		||	(NULL == pp_key)
		||	(NULL == size))
	{
		return NULL;
	}
	return next_keysize(p_ht, p_iterator, pp_key, size);
}

/* Finalize (free) a hash table */
void ght_finalize(ght_hash_table_t *p_ht)
{
	unsigned int i = 0;
	
	if (NULL == p_ht)
	{
		return;
	}

	if (p_ht->pp_entries)
	{
		/* For each bucket, free all entries */
		for (i = 0; i < p_ht->i_size; i++)
		{
			free_entry_chain(p_ht, p_ht->pp_entries[i]);
			p_ht->pp_entries[i] = NULL;
		}
		p_ht->fn_free(p_ht->pp_entries);
		p_ht->pp_entries = NULL;
	}
	if (p_ht->p_nr)
	{
		p_ht->fn_free(p_ht->p_nr);
		p_ht->p_nr = NULL;
	}

	p_ht->fn_free(p_ht);
}

/* Rehash the hash table (i.e. change its size and reinsert all
 * items). This operation is slow and should not be used frequently.
 */
void ght_rehash(ght_hash_table_t *p_ht, unsigned int i_size)
{
	ght_hash_table_t *p_tmp = NULL;
	ght_iterator_t iterator = { 0 };
	const void *p_key = NULL;
	void *p = NULL;
	unsigned int i = 0;

	if (	(NULL == p_ht)
		||	(0 == i_size))
	{
		return;
	}

	/* Recreate the hash table with the new size */
	p_tmp = ght_create(i_size, p_ht->fn_alloc, p_ht->fn_free, p_ht->fn_hash);
	if (NULL == p_tmp)
	{
		return;
	}

	/* Set the flags for the new hash table */
	ght_set_hash(p_tmp, p_ht->fn_hash);
	ght_set_alloc(p_tmp, p_ht->fn_alloc, p_ht->fn_free);
	ght_set_heuristics(p_tmp, GHT_HEURISTICS_NONE);
	ght_set_rehash(p_tmp, FALSE);

	/* Walk through all elements in the table and insert them into the temporary one. */
	for (p = ght_first(p_ht, &iterator, &p_key); p; p = ght_next(p_ht, &iterator, &p_key))
	{
		// DEBUG_ASSERT(iterator.p_entry);

		/* Insert the entry into the new table */
		if (ght_insert(p_tmp,
				iterator.p_entry->p_data,
				iterator.p_entry->key.i_size,
				iterator.p_entry->key.p_key)
			< 0)
		{
			// LOG_ERROR("Out of memory error or entry already in hash table when rehashing (internal error)\n");
		}
	}

	/* Remove the old table... */
	for (i = 0; i < p_ht->i_size; i++)
	{
		if (p_ht->pp_entries[i])
		{
			/* Delete the entries in the bucket */
			free_entry_chain(p_ht, p_ht->pp_entries[i]);
			p_ht->pp_entries[i] = NULL;
		}
	}

	p_ht->fn_free(p_ht->pp_entries);
	p_ht->fn_free(p_ht->p_nr);

	/* ... and replace it with the new */
	p_ht->i_size = p_tmp->i_size;
	p_ht->i_size_mask = p_tmp->i_size_mask;
	p_ht->i_items = p_tmp->i_items;
	p_ht->pp_entries = p_tmp->pp_entries;
	p_ht->p_nr = p_tmp->p_nr;

	p_ht->p_oldest = p_tmp->p_oldest;
	p_ht->p_newest = p_tmp->p_newest;

	/* Clean up */
	p_tmp->pp_entries = NULL;
	p_tmp->p_nr = NULL;
	p_ht->fn_free(p_tmp);
}
