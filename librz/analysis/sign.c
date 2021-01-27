// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_sign.h>
#include <rz_search.h>
#include <rz_core.h>
#include <rz_msg_digest.h>

RZ_LIB_VERSION(rz_sign);

#define SIGN_DIFF_MATCH_BYTES_THRESHOLD 1.0
#define SIGN_DIFF_MATCH_GRAPH_THRESHOLD 1.0

static inline const char *rz_sign_space_name(RzSignItem *it) {
	return it->space ? it->space->name: "*";
}

static void free_zign(HtPPKv *kv) {
	rz_sign_item_free(kv->value);
}

static ut32 hash_zign(const void *obj) {
	RzSignItem *it = (RzSignItem *)obj;
	ut32 hash = sdb_hash(it->name);
	hash ^= sdb_hash(rz_sign_space_name(it));
	return hash;
}

static int cmp_zign(const void *obj1, const void *obj2) {
	RzSignItem *it1 = (RzSignItem *)obj1;
	RzSignItem *it2 = (RzSignItem *)obj2;
	int ret = strcmp(it1->name, it2->name);
	if (ret) {
		return ret;
	}
	return strcmp(rz_sign_space_name(it1), rz_sign_space_name(it2));
}

RZ_IPI void rz_analysis_zigns_storage_init(RzAnalysis *a) {
	HtPPOptions opts = { 0 };
	opts.hashfn = hash_zign;
	opts.cmp = cmp_zign;
	opts.freefn = free_zign;
	a->zigns_ht = ht_pp_new_opt(&opts);
}

const RzFlagItem *getRealRef(RzCore *core, ut64 off) {
	RzFlagItem *item;
	RzListIter *iter;

	const RzList *list = rz_flag_get_list(core->flags, off);
	if (!list) {
		return NULL;
	}

	RzFlagItem *ret = NULL;
	rz_list_foreach (list, iter, item) {
		if (!item->name || !item->size) {
			continue;
		}
		if (item->space && !strcmp(item->space->name, RZ_FLAGS_FS_SYMBOLS)) {
			return item;
		}
		if (!strncmp(item->name, "sym.", 4) || !strncmp(item->name, "fcn.", 4)) {
			ret = item;
		}
	}

	return ret;
}

RZ_API RzList *rz_sign_fcn_vars(RzAnalysis *a, RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(a && fcn, NULL);

	RzCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RzListIter *iter;
	RzAnalysisVar *var;
	RzList *ret = rz_list_newf((RzListFree)free);
	if (!ret) {
		return NULL;
	}
	RzList *reg_vars = rz_analysis_var_list(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_REG);
	RzList *spv_vars = rz_analysis_var_list(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_SPV);
	RzList *bpv_vars = rz_analysis_var_list(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_BPV);
	rz_list_foreach (bpv_vars, iter, var) {
		rz_list_append(ret, rz_str_newf("b%d", var->delta));
	}
	rz_list_foreach (spv_vars, iter, var) {
		rz_list_append(ret, rz_str_newf("s%d", var->delta));
	}
	rz_list_foreach (reg_vars, iter, var) {
		rz_list_append(ret, rz_str_newf("r%d", var->delta));
	}
	rz_list_free(reg_vars);
	rz_list_free(bpv_vars);
	rz_list_free(spv_vars);
	return ret;
}

RZ_API RzList *rz_sign_fcn_types(RzAnalysis *a, RzAnalysisFunction *fcn) {

	// Get key-value types from types db fcn->name
	// Get number of function args
	// Get type,name pairs
	// Put everything in RzList following the next format:
	// types: main.ret=%type%, main.args=%num%, main.arg.0="int,argc", ...

	rz_return_val_if_fail(a && fcn, NULL);

	RzList *ret = rz_list_newf((RzListFree)free);
	if (!ret) {
		return NULL;
	}

	int fcnargs = rz_type_func_args_count(a->typedb, fcn->name);
	const char *ret_type = rz_type_func_ret(a->typedb, fcn->name);

	if (ret_type) {
		rz_list_append(ret, rz_str_newf("func.%s.ret=%s", fcn->name, ret_type));
	}
	if (fcnargs) {
		rz_list_append(ret, rz_str_newf("func.%s.args=%d", fcn->name, fcnargs));
		int i;
		for (i = 0; i < fcnargs; i++) {
			const char *arg_name = rz_type_func_args_name(a->typedb, fcn->name, i);
			const char *arg_type = rz_type_func_args_type(a->typedb, fcn->name, i);
			rz_list_append(ret, rz_str_newf("func.%s.arg.%d=\"%s,%s\"", fcn->name, i, arg_type, arg_name));
		}
	}

	return ret;
}

RZ_API RzList *rz_sign_fcn_xrefs_to(RzAnalysis *a, RzAnalysisFunction *fcn) {
	RzListIter *iter = NULL;
	RzAnalysisXRef *xrefi = NULL;

	rz_return_val_if_fail(a && fcn, NULL);

	RzCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)free);
	RzList *xrefs = rz_analysis_function_get_xrefs_to(fcn);
	rz_list_foreach (xrefs, iter, xrefi) {
		if (xrefi->type == RZ_ANALYSIS_REF_TYPE_CODE || xrefi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
			const RzFlagItem *flag = getRealRef(core, xrefi->from);
			if (flag) {
				rz_list_append(ret, rz_str_new(flag->name));
			}
		}
	}
	rz_list_free(xrefs);
	return ret;
}

RZ_API RzList *rz_sign_fcn_xrefs_from(RzAnalysis *a, RzAnalysisFunction *fcn, RzList **inner_refs) {
	RzListIter *iter = NULL;
	RzAnalysisXRef *xrefi = NULL;

	rz_return_val_if_fail(a && fcn, NULL);

	RzCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RzList *irefs = NULL;
	if (inner_refs) {
		irefs = rz_list_new();
		*inner_refs = irefs;
	}

	RzList *ret = rz_list_newf((RzListFree)free);
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xrefi) {
		if (xrefi->type == RZ_ANALYSIS_REF_TYPE_CODE || xrefi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
			if (irefs && rz_analysis_function_contains(fcn, xrefi->to)) {
				RzSignInnerXref *ir = RZ_NEW0(RzSignInnerXref);
				if (ir) {
					ir->src_offset = xrefi->from - fcn->addr;
					ir->dst_offset = xrefi->to - fcn->addr;
					rz_list_append(irefs, ir);
					continue;
				}
			}
			const RzFlagItem *flag = getRealRef(core, xrefi->to);
			if (!flag) {
				continue;
			}
			RzSignXrefInfo *r = RZ_NEW0(RzSignXrefInfo);
			if (r) {
				r->offset = xrefi->from - fcn->addr;
				r->size = flag->size; // TODO: should be zero in case of sym.imp.*
				r->name = strdup(flag->name);
				rz_list_append(ret, r);
			}
		}
	}
	rz_list_free(xrefs);
	return ret;
}

static RzList *zign_types_to_list(RzAnalysis *a, const char *types) {
	RzList *ret = rz_list_newf((RzListFree)free);
	if (!ret) {
		return NULL;
	}

	unsigned int i = 0, prev = 0, len = strlen(types);
	bool quoted = false;
	char *token = NULL;
	for (i = 0; i <= len; i++) {
		if (types[i] == '"') {
			quoted = !quoted;
		} else if ((types[i] == ',' && !quoted) || types[i] == '\0') {
			token = rz_str_ndup(types + prev, i - prev);
			if (token) {
				prev = i + 1;
				rz_list_append(ret, token);
				token = NULL;
			}
		}
	}

	return ret;
}

static RzList *do_reflike_sig(const char *token) {
	RzList *list = NULL;
	char *scratch = rz_str_new(token);
	int cnt = rz_str_split(scratch, ',');
	if (cnt > 0 && (list = rz_list_newf((RzListFree)free))) {
		int i;
		for (i = 0; i < cnt; i++) {
			rz_list_append(list, rz_str_new(rz_str_word_get0(scratch, i)));
		}
	}
	free(scratch);
	return list;
}

#define DBL_VAL_FAIL(x, y) \
	if (x) { \
		eprintf("Warning: Skipping signature with multiple %c signatures (%s)\n", y, k); \
		success = false; \
		goto out; \
	}
RZ_API bool rz_sign_deserialize(RzAnalysis *a, RzSignItem *it, const char *k, const char *v) {
	rz_return_val_if_fail(a && it && k && v, false);

	bool success = true;
	char *v2 = strdup(v);
	if (!v2) {
		success = false;
		goto out;
	}

	RzJson *json = rz_json_parse(v2);
	if (!json || json->type != RZ_JSON_OBJECT) {
		rz_json_free(json);
		success = false;
		goto out;
	}

	const RzJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (!strcmp(child->key, "name")) {
			if (child->type == RZ_JSON_STRING) {
				it->name = strdup(child->str_value);
			}
			continue;
		}
		if (!strcmp(child->key, "realname")) {
			if (child->type == RZ_JSON_STRING) {
				it->realname = strdup(child->str_value);
			}
			continue;
		}
		if (!strcmp(child->key, "space")) {
			if (child->type == RZ_JSON_STRING) {
				it->space = rz_spaces_add(&a->zign_spaces, child->str_value);
			}
			continue;
		}
		if (!strcmp(child->key, "bytes")) {
			if (child->type == RZ_JSON_OBJECT) {
				const char *hex_bytes, *hex_mask;
				const RzJson *obj;
				obj = rz_json_get(child, "size");
				if (!obj || obj->type != RZ_JSON_INTEGER) {
					eprintf("bytes -> size\n");
					success = false;
					goto out;
				}
				ut64 size = obj->num.u_value;
				obj = rz_json_get(child, "bytes");
				if (!obj || obj->type != RZ_JSON_STRING) {
					eprintf("bytes -> bytes\n");
					success = false;
					goto out;
				}
				hex_bytes = obj->str_value;
				obj = rz_json_get(child, "mask");
				if (!obj || obj->type != RZ_JSON_STRING) {
					eprintf("bytes -> mask\n");
					success = false;
					goto out;
				}
				hex_mask = obj->str_value;
				if (strlen(hex_bytes) != (2 * size) || strlen(hex_mask) != (2 * size)) {
					eprintf ("bytes -> invalid len\n");
					success = false;
					goto out;
				}
				RzSignBytes *b = RZ_NEW0 (RzSignBytes);
				char *bytes = malloc(size);
				char *mask = malloc(size);
				if (!b || !bytes || !mask) {
					eprintf ("bytes -> malloc failed\n");
					free(b);
					free(bytes);
					free(mask);
					success = false;
					goto out;
				}
				rz_hex_str2bin(hex_bytes, bytes);
				rz_hex_str2bin(hex_mask, mask);
				b->size = size;
				b->bytes = bytes;
				b->mask = mask;
				it->bytes = b;
			}
			continue;
		}
		if (!strcmp(child->key, "refs")) {
			if (child->type == RZ_JSON_ARRAY) {
				it->refs = rz_list_newf(free);
				if (!it->refs) {
				    continue;
				}
				const RzJson *baby;
				for (baby = child->children.first; baby; baby = baby->next) {
					if (baby->type == RZ_JSON_OBJECT) {
						const RzJson *obj;
						obj = rz_json_get(baby, "size");
						if (obj->type != RZ_JSON_INTEGER) {
							continue;
						}
						ut64 size = obj->num.u_value;
						obj = rz_json_get(baby, "offset");
						if (obj->type != RZ_JSON_INTEGER) {
						    continue;
						}
						st64 offset = obj->num.s_value;
						obj = rz_json_get(baby, "name");
						if (obj->type != RZ_JSON_STRING) {
						    continue;
						}
						RzSignXrefInfo *r = RZ_NEW0(RzSignXrefInfo);
						if (r) {
							r->size = size;
							r->offset = offset;
							r->name = strdup(obj->str_value);
							rz_list_append(it->refs, r);
						}
					}
				}
			}
			continue;
		}
		if (!strcmp(child->key, "irefs")) {
			if (child->type == RZ_JSON_ARRAY) {
				it->inner_refs = rz_list_newf(free);
				if (!it->inner_refs) {
				    continue;
				}
				const RzJson *baby;
				for (baby = child->children.first; baby; baby = baby->next) {
					if (baby->type == RZ_JSON_OBJECT) {
						const RzJson *obj;
						obj = rz_json_get(baby, "src_offset");
						if (obj->type != RZ_JSON_INTEGER) {
							continue;
						}
						st64 src_offset = obj->num.s_value;
						obj = rz_json_get(baby, "dst_offset");
						if (obj->type != RZ_JSON_INTEGER) {
						    continue;
						}
						st64 dst_offset = obj->num.s_value;
						RzSignInnerXref *r = RZ_NEW0(RzSignInnerXref);
						if (r) {
							r->src_offset = src_offset;
							r->dst_offset = dst_offset;
							rz_list_append(it->inner_refs, r);
						}
					}
				}
			}
			continue;
		}
	}


	/*// remove newline at end
	strtok (v2, "\n");
	// Deserialize value: |k:v|k:v|k:v|...
	n = rz_str_split(v2, '|');
	const char *token = NULL;
	int w, size;
	for (w = 0; w < n; w++) {
		const char *word = rz_str_word_get0(v2, w);
		if (!word) {
			break;
		}
		if (!*word) {
			continue;
		}
		token = word + 2;
		if (!strcmp(word, "*")) {
			continue;
		}
		if (strlen(word) < 3 || word[1] != ':') {
			eprintf("Warning: Skipping signature with corrupted serialization (%s:%s)\n", k, word);
			success = false;
			goto out;
		}
		RzSignType st = (RzSignType)*word;
		switch (st) {
		case RZ_SIGN_ANALYSIS:
			eprintf("Unsupported\n");
			break;
		case RZ_SIGN_NAME:
			DBL_VAL_FAIL(it->realname, RZ_SIGN_NAME);
			it->realname = strdup(token);
			break;
		case RZ_SIGN_COMMENT:
			DBL_VAL_FAIL(it->comment, RZ_SIGN_COMMENT);
			it->comment = strdup(token);
			break;
		case RZ_SIGN_GRAPH: {
			DBL_VAL_FAIL(it->graph, RZ_SIGN_GRAPH);
			char *s = strdup(token);
			if (!s) {
				break;
			}
			size_t gn = rz_str_split(s, ',');
			if (gn == 5) {
				it->graph = RZ_NEW0(RzSignGraph);
				const char *t = s;
				it->graph->cc = atoi(t);
				t = rz_str_word_get_next0(t);
				it->graph->nbbs = atoi(t);
				t = rz_str_word_get_next0(t);
				it->graph->edges = atoi(t);
				t = rz_str_word_get_next0(t);
				it->graph->ebbs = atoi(t);
				t = rz_str_word_get_next0(t);
				it->graph->bbsum = atoi(t);
			}
			free(s);
			break;
		}
		case RZ_SIGN_OFFSET:
			DBL_VAL_FAIL((it->addr != UT64_MAX), RZ_SIGN_OFFSET);
			it->addr = atoll(token);
			break;
		case RZ_SIGN_REFS:
			DBL_VAL_FAIL(it->xrefs_from, RZ_SIGN_REFS);
			if (!(it->xrefs_from = do_reflike_sig(token))) {
				success = false;
				goto out;
			}
			break;
		case RZ_SIGN_XREFS:
			DBL_VAL_FAIL(it->xrefs_to, RZ_SIGN_XREFS);
			if (!(it->xrefs_to = do_reflike_sig(token))) {
				success = false;
				goto out;
			}
			break;
		case RZ_SIGN_VARS:
			DBL_VAL_FAIL(it->vars, RZ_SIGN_VARS);
			if (!(it->vars = do_reflike_sig(token))) {
				success = false;
				goto out;
			}
			break;
		case RZ_SIGN_TYPES:
			DBL_VAL_FAIL(it->types, RZ_SIGN_TYPES);
			it->types = zign_types_to_list(a, token);
			break;
		case RZ_SIGN_BBHASH:
			DBL_VAL_FAIL(it->hash, RZ_SIGN_BBHASH);
			if (token[0] != 0) {
				it->hash = RZ_NEW0(RzSignHash);
				if (it->hash) {
					it->hash->bbhash = rz_str_new(token);
				}
			}
			break;
		case RZ_SIGN_BYTES:
			// following two errors are not due to double entries
			if (!it->bytes) {
				eprintf("Warning: Skipping signature with no bytes size (%s)\n", k);
				success = false;
				goto out;
			}
			if (strlen(token) != 2 * it->bytes->size) {
				eprintf("Warning: Skipping signature with invalid size (%s)\n", k);
				success = false;
				goto out;
			}
			DBL_VAL_FAIL(it->bytes->bytes, RZ_SIGN_BYTES);
			it->bytes->bytes = malloc(it->bytes->size);
			if (it->bytes->bytes) {
				rz_hex_str2bin(token, it->bytes->bytes);
			}
			break;
		case RZ_SIGN_BYTES_MASK:
			// following two errors are not due to double entries
			if (!it->bytes) {
				eprintf("Warning: Skipping signature with no mask size (%s)\n", k);
				success = false;
				goto out;
			}
			if (strlen(token) != 2 * it->bytes->size) {
				eprintf("Warning: Skipping signature invalid mask size (%s)\n", k);
				success = false;
				goto out;
			}
			DBL_VAL_FAIL(it->bytes->mask, RZ_SIGN_BYTES);
			it->bytes->mask = malloc(it->bytes->size);
			if (!it->bytes->mask) {
				goto out;
			}
			rz_hex_str2bin(token, it->bytes->mask);
			break;
		case RZ_SIGN_BYTES_SIZE:
			// allocate
			size = atoi(token);
			if (size > 0) {
				DBL_VAL_FAIL(it->bytes, RZ_SIGN_BYTES_SIZE);
				it->bytes = RZ_NEW0(RzSignBytes);
				if (!it->bytes) {
					goto out;
				}
				it->bytes->size = size;
			}
			break;
		default:
			eprintf("Unsupported (%s)\n", word);
			break;
		}
	}*/
out:
	free(v2);
	return success;
}
#undef DBL_VAL_FAIL

static void mergeItem(RzSignItem *dst, RzSignItem *src) {
	RzListIter *iter = NULL;
	char *ref, *var, *type;

	if (src->bytes) {
		rz_sign_bytes_free(dst->bytes);
		dst->bytes = RZ_NEW0(RzSignBytes);
		if (!dst->bytes) {
			return;
		}
		dst->space = src->space;
		dst->bytes->size = src->bytes->size;
		dst->bytes->bytes = malloc(src->bytes->size);
		if (!dst->bytes->bytes) {
			rz_sign_bytes_free(dst->bytes);
			return;
		}
		memcpy(dst->bytes->bytes, src->bytes->bytes, src->bytes->size);
		dst->bytes->mask = malloc(src->bytes->size);
		if (!dst->bytes->mask) {
			rz_sign_bytes_free(dst->bytes);
			return;
		}
		memcpy(dst->bytes->mask, src->bytes->mask, src->bytes->size);
	}

	if (src->graph) {
		free(dst->graph);
		dst->graph = RZ_NEW0(RzSignGraph);
		if (!dst->graph) {
			return;
		}
		*dst->graph = *src->graph;
	}

	if (src->comment) {
		dst->comment = strdup(src->comment);
	}

	if (src->realname) {
		dst->realname = strdup(src->realname);
	}

	if (src->addr != UT64_MAX) {
		dst->addr = src->addr;
	}

	if (src->xrefs_from) {
		rz_list_free(dst->xrefs_from);

		dst->xrefs_from = rz_list_newf((RzListFree)free);
		rz_list_foreach (src->xrefs_from, iter, ref) {
			rz_list_append(dst->xrefs_from, rz_str_new(ref));
		}
	}

	if (src->vars) {
		rz_list_free(dst->vars);

		dst->vars = rz_list_newf((RzListFree)free);
		rz_list_foreach (src->vars, iter, var) {
			rz_list_append(dst->vars, rz_str_new(var));
		}
	}

	if (src->types) {
		rz_list_free(dst->types);

		dst->types = rz_list_newf((RzListFree)free);
		rz_list_foreach (src->types, iter, type) {
			rz_list_append(dst->types, rz_str_new(type));
		}
	}

	if (src->hash) {
		if (!dst->hash) {
			dst->hash = RZ_NEW0(RzSignHash);
			if (!dst->hash) {
				return;
			}
		}
		if (src->hash->bbhash) {
			dst->hash->bbhash = strdup(src->hash->bbhash);
		}
	}
}

RZ_API RzSignItem *rz_sign_get_item(RzAnalysis *a, const char *name) {
	rz_return_val_if_fail(a && name, NULL);

	RzSignItem key;
	key.name = name;
	key.space = rz_spaces_current(&a->zign_spaces);

	RzSignItem *it = ht_pp_find(a->zigns_ht, &key, NULL);
	if (!it) {
		return NULL;
	}
	RzSignItem *ret = rz_sign_item_new();
	if (ret) {
		mergeItem(ret, it);
	}
	return it;
}

RZ_API bool rz_sign_add_item(RzAnalysis *a, RzSignItem *it) {
	rz_return_val_if_fail(a && it, false);

	RzSignItem *curit = ht_pp_find(a->zigns_ht, it, NULL);
	if (curit) {
		mergeItem(curit, it);
	} else {
		ht_pp_insert(a->zigns_ht, it, it);
	}

	return true;
}

static bool addHash(RzAnalysis *a, const char *name, int type, const char *val) {
	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		rz_sign_item_free(it);
		return false;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		rz_sign_item_free(it);
		return false;
	}
	it->hash = RZ_NEW0(RzSignHash);
	if (!it->hash) {
		rz_sign_item_free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);

	bool retval = false;
	switch (type) {
	case RZ_SIGN_BBHASH:
		it->hash->bbhash = strdup(val);
		retval = rz_sign_add_item(a, it);
		rz_sign_item_free(it);
		break;
	}

	return retval;
}

static bool addBBHash(RzAnalysis *a, RzAnalysisFunction *fcn, const char *name) {
	bool retval = false;
	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		goto beach;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		goto beach;
	}
	it->space = rz_spaces_current(&a->zign_spaces);

	if (rz_sign_addto_item(a, it, fcn, RZ_SIGN_BBHASH)) {
		retval = rz_sign_add_item(a, it);
	}
beach:
	rz_sign_item_free(it);
	return retval;
}

static bool addBytes(RzAnalysis *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	bool retval = true;

	if (rz_mem_is_zero(mask, size)) {
		eprintf("error: zero mask\n");
		return false;
	}

	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}

	it->name = rz_str_new(name);
	if (!it->name) {
		free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);
	it->bytes = RZ_NEW0(RzSignBytes);
	if (!it->bytes) {
		goto fail;
	}
	it->bytes->size = size;
	it->bytes->bytes = malloc(size);
	if (!it->bytes->bytes) {
		goto fail;
	}
	memcpy(it->bytes->bytes, bytes, size);
	it->bytes->mask = malloc(size);
	if (!it->bytes->mask) {
		goto fail;
	}
	memcpy(it->bytes->mask, mask, size);
	retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);
	return retval;
fail:
	if (it) {
		free(it->name);
		rz_sign_bytes_free(it->bytes);
	}
	free(it);
	return false;
}

RZ_API bool rz_sign_add_hash(RzAnalysis *a, const char *name, int type, const char *val, int len) {
	rz_return_val_if_fail(a && name && type && val && len > 0, false);
	if (type != RZ_SIGN_BBHASH) {
		eprintf("error: hash type unknown");
		return false;
	}
	int digestsize = ZIGN_HASH_SIZE * 2;
	if (len != digestsize) {
		eprintf("error: invalid hash size: %d (%s digest size is %d)\n", len, ZIGN_HASH, digestsize);
		return false;
	}
	return addHash(a, name, type, val);
}

RZ_API bool rz_sign_add_bb_hash(RzAnalysis *a, RzAnalysisFunction *fcn, const char *name) {
	rz_return_val_if_fail(a && fcn && name, false);
	return addBBHash(a, fcn, name);
}

RZ_API bool rz_sign_add_bytes(RzAnalysis *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	rz_return_val_if_fail(a && name && size > 0 && bytes && mask, false);
	return addBytes(a, name, size, bytes, mask);
}

RZ_API bool rz_sign_add_analysis(RzAnalysis *a, const char *name, ut64 size, const ut8 *bytes, ut64 at) {
	bool retval = false;
	rz_return_val_if_fail(a && name && size > 0 && bytes, false);
	ut8 *mask = rz_analysis_mask(a, size, bytes, at);
	if (mask) {
		retval = addBytes(a, name, size, bytes, mask);
		free(mask);
	}
	return retval;
}

static RzSignGraph *rz_sign_fcn_graph(RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, false);
	RzSignGraph *graph = RZ_NEW0(RzSignGraph);
	if (graph) {
		graph->cc = rz_analysis_function_complexity(fcn),
		graph->nbbs = rz_list_length(fcn->bbs);
		graph->edges = rz_analysis_function_count_edges(fcn, &graph->ebbs);
		graph->bbsum = rz_analysis_function_realsize(fcn);
	}
	return graph;
}

static int bb_sort_by_addr(const void *x, const void *y) {
	RzAnalysisBlock *a = (RzAnalysisBlock *)x;
	RzAnalysisBlock *b = (RzAnalysisBlock *)y;
	if (a->addr > b->addr) {
		return 1;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	return 0;
}

static RzSignBytes *rz_sign_fcn_bytes(RzAnalysis *a, RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(a && fcn && fcn->bbs && fcn->bbs->head, false);

	// get size
	RzCore *core = a->coreb.core;
	int maxsz = a->coreb.cfggeti(core, "zign.maxsz");
	rz_list_sort(fcn->bbs, &bb_sort_by_addr);
	ut64 ea = fcn->addr;
	RzAnalysisBlock *bb = (RzAnalysisBlock *)fcn->bbs->tail->data;
	int size = RZ_MIN(bb->addr + bb->size - ea, maxsz);

	// alloc space for signature
	RzSignBytes *sig = RZ_NEW0(RzSignBytes);
	if (!sig) {
		goto bytes_failed;
	}
	if (!(sig->bytes = malloc(size))) {
		goto bytes_failed;
	}
	if (!(sig->mask = malloc(size))) {
		goto bytes_failed;
	}
	memset(sig->mask, 0, size);
	sig->size = size;

	// fill in bytes
	if (!a->iob.read_at(a->iob.io, ea, sig->bytes, size)) {
		eprintf("error: failed to read at 0x%08" PFMT64x "\n", ea);
		goto bytes_failed;
	}

	ut8 *tmpmask = NULL;
	RzListIter *iter;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr >= ea) {
			ut64 delta = bb->addr - ea;
			ut64 rsize = bb->size;

			// bounds check
			if (delta > size) {
				break;
			}
			if (size - delta < rsize) {
				rsize = size - delta;
			}

			// get mask for block
			if (!(tmpmask = rz_analysis_mask(a, rsize, sig->bytes + delta, ea))) {
				goto bytes_failed;
			}
			memcpy(sig->mask + delta, tmpmask, rsize);
			free(tmpmask);
		}
	}

	return sig;
bytes_failed:
	rz_sign_bytes_free(sig);
	return NULL;
}

static RzSignHash *rz_sign_fcn_bbhash(RzAnalysis *a, RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(a && fcn, NULL);
	RzSignHash *hash = RZ_NEW0(RzSignHash);
	if (!hash) {
		return NULL;
	}

	char *digest_hex = rz_sign_calc_bbhash(a, fcn);
	if (!digest_hex) {
		free(hash);
		return NULL;
	}
	hash->bbhash = digest_hex;
	return hash;
}

RZ_API bool rz_sign_addto_item(RzAnalysis *a, RzSignItem *it, RzAnalysisFunction *fcn, RzSignType type) {
	rz_return_val_if_fail(a && it && fcn, false);
	switch (type) {
	case RZ_SIGN_GRAPH:
		return !it->graph && (it->graph = rz_sign_fcn_graph(fcn));
	case RZ_SIGN_BYTES:
		return !it->bytes && (it->bytes = rz_sign_fcn_bytes(a, fcn));
	case RZ_SIGN_XREFS:
		return !it->xrefs_to && (it->xrefs_to = rz_sign_fcn_xrefs_to(a, fcn));
	case RZ_SIGN_REFS:
		return !it->xrefs_from && (it->xrefs_from = rz_sign_fcn_xrefs_from(a, fcn, &(it->inner_refs)));
	case RZ_SIGN_VARS:
		return !it->vars && (it->vars = rz_sign_fcn_vars(a, fcn));
	case RZ_SIGN_TYPES:
		return !it->types && (it->types = rz_sign_fcn_types(a, fcn));
	case RZ_SIGN_BBHASH:
		return !it->hash && (it->hash = rz_sign_fcn_bbhash(a, fcn));
	case RZ_SIGN_OFFSET:
		it->addr = fcn->addr;
		return true;
	case RZ_SIGN_NAME:
		if (!it->realname && it->name) {
			if (strcmp(it->name, fcn->name)) {
				it->realname = strdup(fcn->name);
			}
			return true;
		}
		break;
	default:
		eprintf("Error: %s Can not handle type %c\n", __FUNCTION__, type);
	}

	return false;
}

RZ_API bool rz_sign_add_graph(RzAnalysis *a, const char *name, RzSignGraph graph) {
	rz_return_val_if_fail(a && !RZ_STR_ISEMPTY(name), false);
	bool retval = true;
	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);
	it->graph = RZ_NEW0(RzSignGraph);
	if (!it->graph) {
		free(it->name);
		free(it);
		return false;
	}
	*it->graph = graph;
	retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);

	return retval;
}

RZ_API bool rz_sign_add_comment(RzAnalysis *a, const char *name, const char *comment) {
	rz_return_val_if_fail(a && name && comment, false);

	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}
	it->name = rz_str_new(name);
	it->space = rz_spaces_current(&a->zign_spaces);
	it->comment = strdup(comment);
	bool retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);
	return retval;
}

RZ_API bool rz_sign_add_name(RzAnalysis *a, const char *name, const char *realname) {
	rz_return_val_if_fail(a && name && realname, false);
	RzSignItem *it = rz_sign_item_new();
	if (it) {
		it->name = rz_str_new(name);
		it->realname = strdup(realname);
		it->space = rz_spaces_current(&a->zign_spaces);
		bool retval = rz_sign_add_item(a, it);
		rz_sign_item_free(it);
		return retval;
	}
	return false;
}

RZ_API bool rz_sign_add_addr(RzAnalysis *a, const char *name, ut64 addr) {
	rz_return_val_if_fail(a && name && addr != UT64_MAX, false);

	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return NULL;
	}
	it->name = rz_str_new(name);
	it->space = rz_spaces_current(&a->zign_spaces);
	it->addr = addr;

	bool retval = rz_sign_add_item(a, it);

	rz_sign_item_free(it);

	return retval;
}

RZ_API bool rz_sign_add_vars(RzAnalysis *a, const char *name, RzList *vars) {
	rz_return_val_if_fail(a && name && vars, false);

	RzListIter *iter;
	char *var;

	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		rz_sign_item_free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);
	it->vars = rz_list_newf((RzListFree)free);
	rz_list_foreach (vars, iter, var) {
		rz_list_append(it->vars, strdup(var));
	}
	bool retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);

	return retval;
}

RZ_API bool rz_sign_add_types(RzAnalysis *a, const char *name, RzList *types) {
	rz_return_val_if_fail(a && name && types, false);

	RzListIter *iter;
	char *type;

	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		rz_sign_item_free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);
	it->types = rz_list_newf((RzListFree)free);
	rz_list_foreach (types, iter, type) {
		rz_list_append(it->types, strdup(type));
	}
	bool retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);

	return retval;
}

RZ_API bool rz_sign_add_refs(RzAnalysis *a, const char *name, RzList *refs) {
	rz_return_val_if_fail(a && name && refs, false);

	char *ref;
	RzListIter *iter;
	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);
	it->xrefs_from = rz_list_newf((RzListFree)free);
	rz_list_foreach (refs, iter, ref) {
		rz_list_append(it->xrefs_from, strdup(ref));
	}
	bool retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);

	return retval;
}

RZ_API bool rz_sign_add_xrefs(RzAnalysis *a, const char *name, RzList *xrefs) {
	rz_return_val_if_fail(a && name && xrefs, false);

	RzListIter *iter = NULL;
	char *ref = NULL;
	RzSignItem *it = rz_sign_item_new();
	if (!it) {
		return false;
	}
	it->name = rz_str_new(name);
	if (!it->name) {
		free(it);
		return false;
	}
	it->space = rz_spaces_current(&a->zign_spaces);
	it->xrefs_to = rz_list_newf((RzListFree)free);
	rz_list_foreach (xrefs, iter, ref) {
		rz_list_append(it->xrefs_to, strdup(ref));
	}
	bool retval = rz_sign_add_item(a, it);
	rz_sign_item_free(it);

	return retval;
}

typedef struct get_list_by_space_ctx {
	RzSpace *space;
	RzList *list;
} GetListBySpaceCtx;

bool getListBySpaceCb(void *user, const void *k, const void *v) {
	GetListBySpaceCtx *ctx = (GetListBySpaceCtx *)user;
	RzSignItem *it =  (RzSignItem *)v;
	if (it->space == ctx->space) {
		rz_list_append(ctx->list, it);
	}
	return true;
}

static RzList *get_list_by_space(RzAnalysis *a, RzSpace *space) {
	GetListBySpaceCtx ctx;
	RzList *ret = rz_list_new();
	ctx.space = space;
	ctx.list = ret;
	if (ret) {
		ht_pp_foreach(a->zigns_ht, &getListBySpaceCb, &ctx);
	}
	return ret;
}

RZ_API bool rz_sign_delete(RzAnalysis *a, const char *name) {
	rz_return_val_if_fail(a && name, false);

	// Remove all zigns
	if (*name == '*') {
		if (!rz_spaces_current(&a->zign_spaces)) { /* What exactly we should do? */
			ht_pp_free(a->zigns_ht);
			rz_analysis_zigns_storage_init(a);
			return !!a->zigns_ht;
		}
		RzListIter *iter;
		RzSignItem *item;
		RzList *list = get_list_by_space(a, rz_spaces_current(&a->zign_spaces));
		rz_list_foreach (list, iter, item) {
			ht_pp_delete(a->zigns_ht, item);
		}
		rz_list_free(list);
		return true;
	}
	RzSignItem key;
	key.name = name;
	key.space = rz_spaces_current(&a->zign_spaces);
	return ht_pp_delete(a->zigns_ht, &key);
}

static ut8 *build_combined_bytes(RzSignBytes *bsig) {
	rz_return_val_if_fail(bsig && bsig->bytes && bsig->mask, NULL);
	ut8 *buf = (ut8 *)malloc(bsig->size);
	if (buf) {
		size_t i;
		for (i = 0; i < bsig->size; i++) {
			buf[i] = bsig->bytes[i] & bsig->mask[i];
		}
	}
	return buf;
}

static double cmp_bytesig_to_buff(RzSignBytes *sig, ut8 *buf, int len) {
	rz_return_val_if_fail(sig && buf && len >= 0, (double)-1.0);
	ut8 *sigbuf = build_combined_bytes(sig);
	double sim = -1.0;
	if (sigbuf) {
		rz_diff_buffers_distance(NULL, sigbuf, sig->size, buf, len, NULL, &sim);
		free(sigbuf);
	}
	return sim;
}

static double matchBytes(RzSignItem *a, RzSignItem *b) {
	double result = 0.0;

	if (!a->bytes || !b->bytes) {
		return result;
	}

	size_t min_size = RZ_MIN((size_t)a->bytes->size, (size_t)b->bytes->size);
	if (!min_size) {
		return result;
	}

	ut8 *combined_mask = NULL;
	if (a->bytes->mask || b->bytes->mask) {
		combined_mask = (ut8 *)malloc(min_size);
		if (!combined_mask) {
			return result;
		}
		memcpy(combined_mask, a->bytes->mask, min_size);
		if (b->bytes->mask) {
			int i;
			for (i = 0; i != min_size; i++) {
				combined_mask[i] &= b->bytes->mask[i];
			}
		}
	}

	if ((combined_mask && !rz_mem_cmp_mask(a->bytes->bytes, b->bytes->bytes, combined_mask, min_size)) ||
		(!combined_mask && !memcmp(a->bytes->bytes, b->bytes->bytes, min_size))) {
		result = (double)min_size / (double)RZ_MAX(a->bytes->size, b->bytes->size);
	}

	free(combined_mask);

	return result;
}

#define SIMILARITY(a, b) \
	((a) == (b) ? 1.0 : (RZ_MAX((a), (b)) == 0.0 ? 0.0 : (double)RZ_MIN((a), (b)) / (double)RZ_MAX((a), (b))))

static double matchGraph(RzSignItem *a, RzSignItem *b) {
	if (!a->graph || !b->graph) {
		return 0.0;
	}

	double total = 0.0;

	total += SIMILARITY(a->graph->cc, b->graph->cc);
	total += SIMILARITY(a->graph->nbbs, b->graph->nbbs);
	total += SIMILARITY(a->graph->ebbs, b->graph->ebbs);
	total += SIMILARITY(a->graph->edges, b->graph->edges);
	total += SIMILARITY(a->graph->bbsum, b->graph->bbsum);

	return total / 5.0;
}

static int score_cmpr(const void *a, const void *b) {
	double sa = ((RzSignCloseMatch *)a)->score;
	double sb = ((RzSignCloseMatch *)b)->score;

	if (sa < sb) {
		return 1;
	}
	if (sa > sb) {
		return -1;
	}
	return 0;
}

typedef struct {
	RzSignItem *test;
	RzList *output;
	size_t count;
	double score_threshold;
	ut8 *bytes_combined;

	// greatest lower bound. Thanks lattice theory for helping name variables
	double infimum;
} ClosestMatchData;

static bool closest_match_update(ClosestMatchData *data, RzSignItem *it) {
	// quantify how close the signature matches
	int div = 0;
	double score = 0.0;
	double gscore = -1.0;
	if (it->graph && data->test->graph) {
		gscore = matchGraph(it, data->test);
		score += gscore;
		div++;
	}
	double bscore = -1.0;
	bool list_full = (rz_list_length(data->output) == data->count);

	// value to beat to enter the list
	double pivot = data->score_threshold;
	if (list_full) {
		pivot = RZ_MAX(pivot, data->infimum);
	}

	if (it->bytes && data->bytes_combined) {
		int sizea = it->bytes->size;
		int sizeb = data->test->bytes->size;
		if (pivot > 0.0) {
			// bytes distance is slow. To avoid it, we can do quick maths to
			// see if the highest possible score would be good enough to change
			// results
			double maxscore = RZ_MIN(sizea, sizeb) / RZ_MAX(sizea, sizeb);
			if (div > 0) {
				maxscore = (maxscore + score) / div;
			}
			if (maxscore < pivot) {
				rz_sign_item_free(it);
				return true;
			}
		}

		// get true byte score
		bscore = cmp_bytesig_to_buff(it->bytes, data->bytes_combined, sizeb);
		score += bscore;
		div++;
	}
	if (div == 0) {
		rz_sign_item_free(it);
		return true;
	}
	score /= div;

	// score is too low, don't bother doing any more work
	if (score < pivot) {
		rz_sign_item_free(it);
		return true;
	}

	// add new element
	RzSignCloseMatch *row = RZ_NEW(RzSignCloseMatch);
	if (!row) {
		rz_sign_item_free(it);
		return false;
	}
	row->score = score;
	row->gscore = gscore;
	row->bscore = bscore;
	row->item = it;
	rz_list_add_sorted(data->output, (void *)row, &score_cmpr);

	if (list_full) {
		// remove smallest element
		rz_sign_close_match_free(rz_list_pop(data->output));

		// get new infimum
		row = rz_list_get_top(data->output);
		data->infimum = row->score;
	}
	return true;
}

static bool closest_match_callback(void *user, const void *k, const void *v) {
	return closest_match_update((ClosestMatchData *)user, (RzSignItem *)v);
}

RZ_API void rz_sign_close_match_free(RzSignCloseMatch *match) {
	if (match) {
		rz_sign_item_free(match->item);
		free(match);
	}
}

RZ_API RzList *rz_sign_find_closest_sig(RzAnalysis *a, RzSignItem *it, int count, double score_threshold) {
	rz_return_val_if_fail(a && it && count > 0 && score_threshold >= 0 && score_threshold <= 1, NULL);

	// need at least one acceptable signature type
	rz_return_val_if_fail(it->bytes || it->graph, NULL);

	ClosestMatchData data;
	RzList *output = rz_list_newf((RzListFree)rz_sign_close_match_free);
	if (!output) {
		return NULL;
	}

	data.output = output;
	data.count = count;
	data.score_threshold = score_threshold;
	data.infimum = 0.0;
	data.test = it;
	if (it->bytes) {
		data.bytes_combined = build_combined_bytes(it->bytes);
	} else {
		data.bytes_combined = NULL;
	}

	// TODO: handle sign spaces
	ht_pp_foreach(a->zigns_ht, &closest_match_callback, (void *)&data);

	free(data.bytes_combined);
	return output;
}

RZ_API RzList *rz_sign_find_closest_fcn(RzAnalysis *a, RzSignItem *it, int count, double score_threshold) {
	rz_return_val_if_fail(a && it && count > 0 && score_threshold >= 0 && score_threshold <= 1, NULL);
	rz_return_val_if_fail(it->bytes || it->graph, NULL);

	RzList *output = rz_list_newf((RzListFree)rz_sign_close_match_free);
	if (!output) {
		return NULL;
	}

	ClosestMatchData data;
	data.output = output;
	data.count = count;
	data.score_threshold = score_threshold;
	data.infimum = 0.0;
	data.test = it;
	if (it->bytes) {
		data.bytes_combined = build_combined_bytes(it->bytes);
	} else {
		data.bytes_combined = NULL;
	}

	RzAnalysisFunction *fcn;
	RzListIter *iter;
	rz_list_foreach (a->fcns, iter, fcn) {
		// turn function into signature item
		RzSignItem *fsig = rz_sign_item_new();
		if (!fsig) {
			rz_list_free(output);
			return NULL;
		}
		if (data.bytes_combined) {
			rz_sign_addto_item(a, fsig, fcn, RZ_SIGN_BYTES);
		}
		if (it->graph) {
			rz_sign_addto_item(a, fsig, fcn, RZ_SIGN_GRAPH);
		}
		rz_sign_addto_item(a, fsig, fcn, RZ_SIGN_OFFSET);
		fsig->name = rz_str_new(fcn->name);

		// maybe add signature item to output list
		closest_match_update(&data, fsig);
	}
	free(data.bytes_combined);
	return output;
}

RZ_API bool rz_sign_diff(RzAnalysis *a, RzSignOptions *options, const char *other_space_name) {
	rz_return_val_if_fail(a && other_space_name, false);

	RzSpace *current_space = rz_spaces_current(&a->zign_spaces);
	if (!current_space) {
		return false;
	}
	RzSpace *other_space = rz_spaces_get(&a->zign_spaces, other_space_name);
	if (!other_space) {
		return false;
	}

	RzList *la = get_list_by_space(a, current_space);
	if (!la) {
		return false;
	}
	RzList *lb = get_list_by_space(a, other_space);
	if (!lb) {
		rz_list_free(la);
		return false;
	}

	eprintf("Diff %d %d\n", (int)ls_length(la), (int)ls_length(lb));

	RzListIter *itr;
	RzListIter *itr2;
	RzSignItem *si;
	RzSignItem *si2;

	// do the sign diff here
	rz_list_foreach (la, itr, si) {
		if (strstr(si->name, "imp.")) {
			continue;
		}
		rz_list_foreach (lb, itr2, si2) {
			if (strstr(si2->name, "imp.")) {
				continue;
			}
			double bytesScore = matchBytes(si, si2);
			double graphScore = matchGraph(si, si2);
			bool bytesMatch = bytesScore >= (options ? options->bytes_diff_threshold : SIGN_DIFF_MATCH_BYTES_THRESHOLD);
			bool graphMatch = graphScore >= (options ? options->graph_diff_threshold : SIGN_DIFF_MATCH_GRAPH_THRESHOLD);

			if (bytesMatch) {
				a->cb_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %02.5lf B %s\n", si->addr, si2->addr, bytesScore, si->name);
			}

			if (graphMatch) {
				a->cb_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %02.5lf G %s\n", si->addr, si2->addr, graphScore, si->name);
			}
		}
	}

	rz_list_free(la);
	rz_list_free(lb);
	return true;
}

RZ_API bool rz_sign_diff_by_name(RzAnalysis *a, RzSignOptions *options, const char *other_space_name, bool not_matching) {
	rz_return_val_if_fail(a && other_space_name, false);

	RzSpace *current_space = rz_spaces_current(&a->zign_spaces);
	if (!current_space) {
		return false;
	}
	RzSpace *other_space = rz_spaces_get(&a->zign_spaces, other_space_name);
	if (!other_space) {
		return false;
	}

	RzList *la = get_list_by_space(a, current_space);
	if (!la) {
		return false;
	}
	RzList *lb = get_list_by_space(a, other_space);
	if (!lb) {
		rz_list_free(la);
		return false;
	}

	eprintf("Diff by name %d %d (%s)\n", (int)ls_length(la), (int)ls_length(lb), not_matching ? "not matching" : "matching");

	RzListIter *itr;
	RzListIter *itr2;
	RzSignItem *si;
	RzSignItem *si2;

	rz_list_foreach (la, itr, si) {
		if (strstr(si->name, "imp.")) {
			continue;
		}
		rz_list_foreach (lb, itr2, si2) {
			if (strcmp(si->name, si2->name)) {
				continue;
			}
			// TODO: add config variable for threshold
			double bytesScore = matchBytes(si, si2);
			double graphScore = matchGraph(si, si2);
			bool bytesMatch = bytesScore >= (options ? options->bytes_diff_threshold : SIGN_DIFF_MATCH_BYTES_THRESHOLD);
			bool graphMatch = graphScore >= (options ? options->graph_diff_threshold : SIGN_DIFF_MATCH_GRAPH_THRESHOLD);
			if ((bytesMatch && !not_matching) || (!bytesMatch && not_matching)) {
				a->cb_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %02.5f B %s\n", si->addr, si2->addr, bytesScore, si->name);
			}
			if ((graphMatch && !not_matching) || (!graphMatch && not_matching)) {
				a->cb_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %02.5f G %s\n", si->addr, si2->addr, graphScore, si->name);
			}
		}
	}

	rz_list_free(la);
	rz_list_free(lb);

	return true;
}

struct ctxListCB {
	RzAnalysis *analysis;
	int idx;
	int format;
	PJ *pj;
};

struct ctxGetListCB {
	RzAnalysis *analysis;
	RzList *list;
};

static void listBytes(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	RzSignBytes *bytes = it->bytes;

	if (!bytes->bytes) {
		return;
	}

	int masked = 0, i = 0;
	for (i = 0; i < bytes->size; i++) {
		masked += bytes->mask[i] == 0xff;
	}

	char *strbytes = rz_hex_bin2strdup(bytes->bytes, bytes->size);
	if (!strbytes) {
		return;
	}
	char *strmask = rz_hex_bin2strdup(bytes->mask, bytes->size);
	if (!strmask) {
		free(strbytes);
		return;
	}

	if (format == '*') {
		if (masked == bytes->size) {
			a->cb_printf("za %s b %s\n", it->name, strbytes);
		} else {
			a->cb_printf("za %s b %s:%s\n", it->name, strbytes, strmask);
		}
	} else if (format == 'q') {
		a->cb_printf(" b(%d/%d)", masked, bytes->size);
	} else if (format == 'j') {
		pj_ks(pj, "bytes", strbytes);
		pj_ks(pj, "mask", strmask);
	} else {
		a->cb_printf("  bytes: %s\n", strbytes);
		a->cb_printf("  mask: %s\n", strmask);
	}

	free(strbytes);
	free(strmask);
}

static void listGraph(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	RzSignGraph *graph = it->graph;

	if (format == 'q') {
		a->cb_printf(" g(cc=%d,nb=%d,e=%d,eb=%d,h=%d)",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else if (format == '*') {
		a->cb_printf("za %s g cc=%d nbbs=%d edges=%d ebbs=%d bbsum=%d\n",
			it->name, graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else if (format == 'j') {
		pj_ko(pj, "graph");
		pj_kN(pj, "cc", graph->cc);
		pj_kN(pj, "nbbs", graph->nbbs);
		pj_kN(pj, "edges", graph->edges);
		pj_kN(pj, "ebbs", graph->ebbs);
		pj_kN(pj, "bbsum", graph->bbsum);
		pj_end(pj);
	} else {
		a->cb_printf("  graph: cc=%d nbbs=%d edges=%d ebbs=%d bbsum=%d\n",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	}
}

static void listComment(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	if (it->comment) {
		if (format == 'q') {
			//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
			a->cb_printf("\n ; %s\n", it->comment);
		} else if (format == '*') {
			a->cb_printf("%s\n", it->comment); // comment injection via CCu..
		} else if (format == 'j') {
			pj_ks(pj, "comments", it->comment);
		} else {
			a->cb_printf("  comment: 0x%08" PFMT64x "\n", it->addr);
		}
	}
}

static void listRealname(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	if (it->realname) {
		if (format == 'q') {
			//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
		} else if (format == '*') {
			a->cb_printf("za %s n %s\n", it->name, it->realname);
			a->cb_printf("afn %s @ 0x%08" PFMT64x "\n", it->realname, it->addr);
		} else if (format == 'j') {
			pj_ks(pj, "realname", it->realname);
		} else {
			a->cb_printf("  realname: %s\n", it->realname);
		}
	}
}

static void listOffset(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	if (format == 'q') {
		//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
	} else if (format == '*') {
		a->cb_printf("za %s o 0x%08" PFMT64x "\n", it->name, it->addr);
	} else if (format == 'j') {
		pj_kN(pj, "addr", it->addr);
	} else {
		a->cb_printf("  addr: 0x%08" PFMT64x "\n", it->addr);
	}
}

static void listVars(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	RzListIter *iter = NULL;
	char *var = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf("za %s v ", it->name);
	} else if (format == 'q') {
		a->cb_printf(" vars(%d)", rz_list_length(it->vars));
		return;
	} else if (format == 'j') {
		pj_ka(pj, "vars");
	} else {
		a->cb_printf("  vars: ");
	}

	rz_list_foreach (it->vars, iter, var) {
		if (i > 0) {
			if (format == '*') {
				a->cb_printf(" ");
			} else if (format != 'j') {
				a->cb_printf(", ");
			}
		}
		if (format == 'j') {
			pj_s(pj, var);
		} else {
			a->cb_printf("%s", var);
		}
		i++;
	}

	if (format == 'j') {
		pj_end(pj);
	} else {
		a->cb_printf("\n");
	}
}

static void print_list_type_header(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	if (format == '*') {
		a->cb_printf("za %s t ", it->name);
	} else if (format == 'q') {
		a->cb_printf(" types(%d)", rz_list_length(it->types));
		return;
	} else if (format == 'j') {
		pj_ka(pj, "types");
	} else {
		a->cb_printf("  types: ");
	}
}

static void print_function_args_json(RzAnalysis *a, PJ *pj, char *arg_type) {
	char *arg_name = strchr(arg_type, ',');

	if (arg_name == NULL) {
		return;
	}

	*arg_name = '\0';
	++arg_name;

	size_t len_arg_name = strlen(arg_name);
	arg_name[len_arg_name - 1] = '\0';

	pj_o(pj);
	pj_ks(pj, "name", arg_name);
	pj_ks(pj, "type", arg_type + 1);
	pj_end(pj);
}

static void print_type_json(RzAnalysis *a, char *type, PJ *pj, size_t pos) {
	if (pos == 0) {
		return;
	}

	char *str_type = strchr(type, '=');

	if (str_type == NULL) {
		return;
	}

	*str_type = '\0';
	++str_type;

	print_function_args_json(a, pj, str_type);
}

static void print_list_separator(RzAnalysis *a, RzSignItem *it, PJ *pj, int format, int pos) {
	if (pos == 0 || format == 'j') {
		return;
	}
	if (format == '*') {
		a->cb_printf(" ");
	} else {
		a->cb_printf(", ");
	}
}

static void print_list_type_body(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	int i = 0;
	char *type = NULL;
	RzListIter *iter = NULL;

	rz_list_foreach (it->types, iter, type) {
		print_list_separator(a, it, pj, format, i);

		if (format == 'j') {
			char *t = strdup(type);
			print_type_json(a, t, pj, i);
			free(t);
		} else {
			a->cb_printf("%s", type);
		}
		i++;
	}
}

static void listTypes(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	print_list_type_header(a, it, pj, format);
	print_list_type_body(a, it, pj, format);

	if (format == 'j') {
		pj_end(pj);
	} else {
		a->cb_printf("\n");
	}
}

static void listXRefsTo(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	RzListIter *iter = NULL;
	char *ref = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf("za %s x ", it->name);
	} else if (format == 'q') {
		a->cb_printf(" xrefs_to(%d)", rz_list_length(it->xrefs_to));
		return;
	} else if (format == 'j') {
		pj_ka(pj, "xrefs_to");
	} else {
		if (it->xrefs_to && !rz_list_empty(it->xrefs_to)) {
			a->cb_printf("  xrefs_to: ");
		}
	}

	rz_list_foreach (it->xrefs_to, iter, ref) {
		if (i > 0) {
			if (format == '*') {
				a->cb_printf(" ");
			} else if (format != 'j') {
				a->cb_printf(", ");
			}
		}
		if (format == 'j') {
			pj_s(pj, ref);
		} else {
			a->cb_printf("%s", ref);
		}
		i++;
	}

	if (format == 'j') {
		pj_end(pj);
	} else {
		a->cb_printf("\n");
	}
}

static void listXRefsFrom(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	RzListIter *iter = NULL;
	RzSignXrefInfo *ref = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf("za %s r ", it->name);
	} else if (format == 'q') {
		a->cb_printf(" xrefs_from(%d)", rz_list_length(it->xrefs_from));
		return;
	} else if (format == 'j') {
		pj_ka(pj, "xrefs_from");
	} else {
		if (it->xrefs_from && !rz_list_empty(it->xrefs_from)) {
			a->cb_printf("  xrefs_from: ");
		}
	}

	rz_list_foreach (it->xrefs_from, iter, ref) {
		if (i > 0) {
			if (format == '*') {
				a->cb_printf(" ");
			} else if (format != 'j') {
				a->cb_printf(", ");
			}
		}
		if (format == 'j') {
			pj_s(pj, ref->name);
		} else {
			a->cb_printf("%s", ref->name);
		}
		i++;
	}

	if (format == 'j') {
		pj_end(pj);
	} else {
		a->cb_printf("\n");
	}
}

static void listHash(RzAnalysis *a, RzSignItem *it, PJ *pj, int format) {
	if (!it->hash) {
		return;
	}
	switch (format) {
	case 'q':
		if (it->hash->bbhash) {
			a->cb_printf(" h(%08x)", rz_str_hash(it->hash->bbhash));
		}
		break;
	case '*':
		if (it->hash->bbhash) {
			a->cb_printf("za %s h %s\n", it->name, it->hash->bbhash);
		}
		break;
	case 'j':
		pj_ko(pj, "hash");
		if (it->hash->bbhash) {
			pj_ks(pj, "bbhash", it->hash->bbhash);
		}
		pj_end(pj);
		break;
	default:
		if (it->hash->bbhash) {
			a->cb_printf("  bbhash: %s\n", it->hash->bbhash);
		}
		break;
	}
}

static bool listCB(void *user, const char *k, void *v) {
	struct ctxListCB *ctx = (struct ctxListCB *)user;
	RzSignItem *it = (RzSignItem *)v;
	RzAnalysis *a = ctx->analysis;

	RzSpace *cur = rz_spaces_current(&a->zign_spaces);
	if (cur != it->space && cur) {
		return true;
	}

	// Start item
	if (ctx->format == 'j') {
		pj_o(ctx->pj);
	}

	// Zignspace and name (except for rizin format)
	if (ctx->format == '*') {
		if (it->space) {
			a->cb_printf("zs %s\n", it->space->name);
		} else {
			a->cb_printf("zs *\n");
		}
	} else if (ctx->format == 'q') {
		a->cb_printf("0x%08" PFMT64x " ", it->addr);
		const char *pad = rz_str_pad(' ', 30 - strlen(it->name));
		a->cb_printf("%s:%s", it->name, pad);
	} else if (ctx->format == 'j') {
		if (it->space) {
			pj_ks(ctx->pj, "zignspace", it->space->name);
		}
		pj_ks(ctx->pj, "name", it->name);
	} else {
		if (!rz_spaces_current(&a->zign_spaces) && it->space) {
			a->cb_printf("(%s) ", it->space->name);
		}
		a->cb_printf("%s:\n", it->name);
	}

	// Bytes pattern
	if (it->bytes) {
		listBytes(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ks(ctx->pj, "bytes", "");
	}

	// Graph metrics
	if (it->graph) {
		listGraph(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ko(ctx->pj, "graph");
		pj_end(ctx->pj);
	}

	// Offset
	if (it->addr != UT64_MAX) {
		listOffset(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_kN(ctx->pj, "addr", -1);
	}
	// Name
	if (it->realname) {
		listRealname(a, it, ctx->pj, ctx->format);
	}
	if (it->comment) {
		listComment(a, it, ctx->pj, ctx->format);
	}
	// XReferences
	if (it->xrefs_from) {
		listXRefsFrom(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ka(ctx->pj, "xrefs_from");
		pj_end(ctx->pj);
	}
	// XReferences
	if (it->xrefs_to) {
		listXRefsTo(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ka(ctx->pj, "xrefs_to");
		pj_end(ctx->pj);
	}
	// Vars
	if (it->vars) {
		listVars(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ka(ctx->pj, "vars");
		pj_end(ctx->pj);
	}
	if (it->types) {
		listTypes(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ka(ctx->pj, "types");
		pj_end(ctx->pj);
	}
	// Hash
	if (it->hash) {
		listHash(a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ko(ctx->pj, "hash");
		pj_end(ctx->pj);
	}

	// End item
	if (ctx->format == 'j') {
		pj_end(ctx->pj);
	}
	if (ctx->format == 'q') {
		a->cb_printf("\n");
	}

	ctx->idx++;

	return true;
}

RZ_API void rz_sign_list(RzAnalysis *a, int format) {
	rz_return_if_fail(a);
	PJ *pj = NULL;

	if (format == 'j') {
		pj = a->coreb.pjWithEncoding(a->coreb.core);
		pj_a(pj);
	}

	struct ctxListCB ctx = { a, 0, format, pj };
	ht_pp_foreach(a->zigns_ht, listCB, &ctx);

	if (format == 'j') {
		pj_end(pj);
		a->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
}

static bool listGetCB(void *user, const char *key, void *val) {
	struct ctxGetListCB *ctx = user;
	RzSignItem *item = rz_sign_item_new();
	if (!item) {
		return false;
	}
	mergeItem(item, val);
	rz_list_append(ctx->list, item);
	return true;
}

RZ_API RzList *rz_sign_get_list(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);
	RzList *list = rz_list_newf((RzListFree)rz_sign_item_free);
	struct ctxGetListCB ctx = { a, list };
	if (list) {
		ht_pp_foreach(a->zigns_ht, listGetCB, &ctx);
	}
	return list;
}

static int cmpaddr(const void *_a, const void *_b) {
	const RzAnalysisBlock *a = _a, *b = _b;
	return (a->addr - b->addr);
}

RZ_API char *rz_sign_calc_bbhash(RzAnalysis *a, RzAnalysisFunction *fcn) {
	RzListIter *iter = NULL;
	RzAnalysisBlock *bbi = NULL;
	char *digest_hex = NULL;
	RzMsgDigestSize digest_size = 0;
	const ut8 *digest = NULL;
	RzMsgDigest *md = NULL;
	ut8 *buf = NULL;

	md = rz_msg_digest_new_with_algo2(ZIGN_HASH);
	if (!md) {
		goto beach;
	}

	rz_list_sort(fcn->bbs, &cmpaddr);
	rz_list_foreach (fcn->bbs, iter, bbi) {
		buf = malloc(bbi->size);
		if (!buf) {
			goto beach;
		}
		if (!a->iob.read_at(a->iob.io, bbi->addr, buf, bbi->size)) {
			goto beach;
		}
		if (!rz_msg_digest_update(md, buf, bbi->size)) {
			goto beach;
		}
		RZ_FREE(buf);
	}

	if (!rz_msg_digest_final(md) ||
		!(digest = rz_msg_digest_get_result(md, ZIGN_HASH, &digest_size))) {
		goto beach;
	}

	digest_hex = rz_hex_bin2strdup(digest, digest_size);

beach:
	rz_msg_digest_free(md);
	free(buf);
	return digest_hex;
}

struct ctxCountForCB {
	const RzSpace *space;
	int count;
};

static bool countForCB(void *user, const char *k, void *v) {
	struct ctxCountForCB *ctx = (struct ctxCountForCB *)user;
	RzSignItem *it = (RzSignItem *)v;
	if (it->space == ctx->space) {
		ctx->count++;
	}
	return true;
}

RZ_API int rz_sign_space_count_for(RzAnalysis *a, const RzSpace *space) {
	struct ctxCountForCB ctx = { space, 0 };
	rz_return_val_if_fail(a, 0);
	ht_pp_foreach(a->zigns_ht, countForCB, &ctx);
	return ctx.count;
}

RZ_API void rz_sign_space_unset_for(RzAnalysis *a, const RzSpace *space) {
	rz_return_if_fail(a);

	RzListIter *iter;
	RzSignItem *item;
	RzList *list = get_list_by_space(a, space);
	rz_list_foreach (list, iter, item) {
		ht_pp_delete(a->zigns_ht, item);
	}
	rz_list_free(list);
}

RZ_API void rz_sign_space_rename_for(RzAnalysis *a, const RzSpace *space, const char *oname, const char *nname) {
	rz_return_if_fail(a && space && oname && nname);

	RzListIter *iter;
	RzSignItem *item;
	RzList *list = get_list_by_space(a, space);
	RzSpace tmp;
	tmp.name = nname;
	RzSignItem nkey;
	nkey.space = &tmp;
	rz_list_foreach(list, iter, item) {
		nkey.name = item->name;
		ht_pp_update_key(a->zigns_ht, item, &nkey);
	}
}

struct ctxForeachCB {
	RzAnalysis *analysis;
	RzSignForeachCallback cb;
	void *user;
};

static bool foreachCB(void *user, const char *k, void *v) {
	struct ctxForeachCB *ctx = (struct ctxForeachCB *)user;
	RzSignItem *it = (RzSignItem *)v;
	RzAnalysis *a = ctx->analysis;
	RzSpace *cur = rz_spaces_current(&a->zign_spaces);
	if (ctx->cb && cur == it->space) {
		ctx->cb (it, ctx->user);
	}
	return true;
}

RZ_API bool rz_sign_foreach(RzAnalysis *a, RzSignForeachCallback cb, void *user) {
	rz_return_val_if_fail(a && cb, false);
	struct ctxForeachCB ctx = { a, cb, user };
	ht_pp_foreach(a->zigns_ht, foreachCB, &ctx);
	return true;
}

RZ_API RzSignSearch *rz_sign_search_new(void) {
	RzSignSearch *ret = RZ_NEW0(RzSignSearch);
	if (ret) {
		ret->search = rz_search_new(RZ_SEARCH_KEYWORD);
		ret->items = rz_list_new();
	}
	return ret;
}

RZ_API void rz_sign_search_free(RzSignSearch *ss) {
	if (!ss) {
		return;
	}
	rz_search_free(ss->search);
	rz_list_free(ss->items);
	free(ss);
}

static int searchHitCB(RzSearchKeyword *kw, void *user, ut64 addr) {
	RzSignSearch *ss = (RzSignSearch *)user;
	return ss->cb ? ss->cb((RzSignItem *)kw->data, kw, addr, ss->user) : 1;
}

struct ctxAddSearchKwCB {
	RzSignSearch *ss;
	int minsz;
};

static int addSearchKwCB(RzSignItem *it, void *user) {
	struct ctxAddSearchKwCB *ctx = (struct ctxAddSearchKwCB *)user;
	RzSignSearch *ss = ctx->ss;
	RzSignBytes *bytes = it->bytes;

	if (!bytes) {
		eprintf("Cannot find bytes for this signature: %s\n", it->name);
		return 1;
	}

	if (ctx->minsz && bytes->size < ctx->minsz) {
		return 1;
	}
	rz_list_append(ss->items, it);
	RzSearchKeyword *kw = rz_search_keyword_new(bytes->bytes, bytes->size, bytes->mask, bytes->size, (const char *)it);
	rz_search_kw_add(ss->search, kw);
	return 1;
}

RZ_API void rz_sign_search_init(RzAnalysis *a, RzSignSearch *ss, int minsz, RzSignSearchCallback cb, void *user) {
	struct ctxAddSearchKwCB ctx = { ss, minsz };
	rz_return_if_fail(a && ss && cb);
	ss->cb = cb;
	ss->user = user;
	rz_list_purge(ss->items);
	rz_search_reset(ss->search, RZ_SEARCH_KEYWORD);
	rz_sign_foreach(a, addSearchKwCB, &ctx);
	rz_search_begin(ss->search);
	rz_search_set_callback(ss->search, searchHitCB, ss);
}

RZ_API int rz_sign_search_update(RzAnalysis *a, RzSignSearch *ss, ut64 *at, const ut8 *buf, int len) {
	rz_return_val_if_fail(a && ss && buf && len > 0, 0);
	return rz_search_update(ss->search, *at, buf, len);
}

// allow ~10% of margin error
static int matchCount(int a, int b) {
	int c = a - b;
	int m = a / 10;
	return RZ_ABS(c) < m;
}

static bool fcnMetricsCmp(RzSignItem *it, RzAnalysisFunction *fcn) {
	RzSignGraph *graph = it->graph;
	int ebbs = -1;

	if (graph->cc != -1 && graph->cc != rz_analysis_function_complexity(fcn)) {
		return false;
	}
	if (graph->nbbs != -1 && graph->nbbs != rz_list_length(fcn->bbs)) {
		return false;
	}
	if (graph->edges != -1 && graph->edges != rz_analysis_function_count_edges(fcn, &ebbs)) {
		return false;
	}
	if (graph->ebbs != -1 && graph->ebbs != ebbs) {
		return false;
	}
	if (graph->bbsum > 0 && matchCount(graph->bbsum, rz_analysis_function_linear_size(fcn))) {
		return false;
	}
	return true;
}

static bool graph_match(RzSignItem *it, RzSignSearchMetrics *sm) {
	RzSignGraph *graph = it->graph;

	if (!graph) {
		return false;
	}

	if (graph->cc < sm->mincc) {
		return false;
	}

	if (!fcnMetricsCmp(it, sm->fcn)) {
		return false;
	}

	return true;
}

static bool addr_match(RzSignItem *it, RzSignSearchMetrics *sm) {
	if (it->addr != sm->fcn->addr || it->addr == UT64_MAX) {
		return false;
	}
	return true;
}

static bool hash_match(RzSignItem *it, char **digest_hex, RzSignSearchMetrics *sm) {
	RzSignHash *hash = it->hash;
	if (!hash || !hash->bbhash || hash->bbhash[0] == 0) {
		return false;
	}

	if (!*digest_hex) {
		*digest_hex = rz_sign_calc_bbhash(sm->analysis, sm->fcn);
	}
	if (strcmp(hash->bbhash, *digest_hex)) {
		return false;
	}
	return true;
}

static bool str_list_equals(RzList *la, RzList *lb) {
	rz_return_val_if_fail(la && lb, false);
	size_t len = rz_list_length(la);
	if (len != rz_list_length(lb)) {
		return false;
	}
	size_t i;
	for (i = 0; i < len; i++) {
		const char *a = rz_list_get_n(la, i);
		const char *b = rz_list_get_n(lb, i);
		if (strcmp(a, b)) {
			return false;
		}
	}
	return true;
}

static bool vars_match(RzSignItem *it, RzList **vars, RzSignSearchMetrics *sm) {
	rz_return_val_if_fail(vars && sm, false);
	if (!it->vars) {
		return false;
	}

	if (!*vars) {
		*vars = rz_sign_fcn_vars(sm->analysis, sm->fcn);
		if (!*vars) {
			return false;
		}
	}

	if (str_list_equals(*vars, it->vars)) {
		return true;
	}
	return false;
}

static bool xrefs_from_match(RzSignItem *it, RzList **refs, RzSignSearchMetrics *sm) {
	rz_return_val_if_fail(refs && sm, false);
	if (!it->xrefs_from) {
		return false;
	}

	if (!*refs) {
		*refs = rz_sign_fcn_xrefs_from(sm->analysis, sm->fcn, NULL);
		if (!*refs) {
			return false;
		}
	}

	if (str_list_equals(*refs, it->xrefs_from)) {
		return true;
	}
	return false;
}

static bool types_match(RzSignItem *it, RzList **types, RzSignSearchMetrics *sm) {
	rz_return_val_if_fail(types && sm, false);
	if (!it->types) {
		return false;
	}

	if (!*types) {
		*types = rz_sign_fcn_types(sm->analysis, sm->fcn);
		if (!*types) {
			return false;
		}
	}

	if (str_list_equals(*types, it->types)) {
		return true;
	}

	return false;
}

struct metric_ctx {
	int matched;
	RzSignSearchMetrics *sm;
	RzList *xrefs_from;
	RzList *types;
	RzList *vars;
	char *digest_hex;
};

static int match_metrics(RzSignItem *it, void *user) {
	struct metric_ctx *ctx = (struct metric_ctx *)user;
	RzSignSearchMetrics *sm = ctx->sm;
	RzSignType type;
	int count = 0;
	int i = 0;
	while ((type = sm->types[i++])) {
		bool found = false;
		switch (type) {
		case RZ_SIGN_GRAPH:
			found = graph_match(it, sm);
			break;
		case RZ_SIGN_OFFSET:
			found = addr_match(it, sm);
			break;
		case RZ_SIGN_BBHASH:
			found = hash_match(it, &ctx->digest_hex, sm);
			break;
		case RZ_SIGN_REFS:
			found = xrefs_from_match(it, &ctx->xrefs_from, sm);
			break;
		case RZ_SIGN_TYPES:
			found = vars_match(it, &ctx->vars, sm);
			break;
		case RZ_SIGN_VARS:
			found = types_match(it, &ctx->types, sm);
			break;
		default:
			eprintf("Invalid type: %c\n", type);
		}
		if (found) {
			sm->cb(it, sm->fcn, type, (count > 1), sm->user);
			count++;
		}
	}
	ctx->matched += count;
	return count ? 0 : 1;
}

RZ_API int rz_sign_fcn_match_metrics(RzSignSearchMetrics *sm) {
	rz_return_val_if_fail(sm && sm->mincc >= 0 && sm->analysis && sm->fcn, false);
	struct metric_ctx ctx = { 0, sm, NULL, NULL, NULL, NULL };
	rz_sign_foreach(sm->analysis, match_metrics, (void *)&ctx);
	rz_list_free(ctx.xrefs_from);
	rz_list_free(ctx.types);
	rz_list_free(ctx.vars);
	free(ctx.digest_hex);
	return ctx.matched;
}

RZ_API RzSignItem *rz_sign_item_new(void) {
	RzSignItem *ret = RZ_NEW0(RzSignItem);
	if (ret) {
		ret->addr = UT64_MAX;
		ret->space = NULL;
	}
	return ret;
}

RZ_API void rz_sign_item_free(RzSignItem *item) {
	if (!item) {
		return;
	}
	free(item->name);
	rz_sign_bytes_free(item->bytes);
	if (item->hash) {
		free(item->hash->bbhash);
		free(item->hash);
	}
	rz_sign_graph_free(item->graph);
	free(item->comment);
	free(item->realname);
	rz_list_free(item->xrefs_from);
	rz_list_free(item->vars);
	rz_list_free(item->xrefs_to);
	rz_list_free(item->types);
	free(item);
}

RZ_API void rz_sign_graph_free(RzSignGraph *graph) {
	free(graph);
}

RZ_API void rz_sign_bytes_free(RzSignBytes *bytes) {
	if (bytes) {
		free(bytes->bytes);
		free(bytes->mask);
		free(bytes);
	}
}

static bool debug_cmp_sign_bytes(RzSignItem *old, RzSignItem *new) {
	if (!old->bytes || !new->bytes) {
		eprintf("One/Both signs don't contain bytes (old:%d new:%d)\n", !!old->bytes, !!new->bytes);
		return false;
	}
	if (old->bytes->size != new->bytes->size) {
		eprintf("Different bytes size\n");
		return false;
	}
	for (int i = 0; i < old->bytes->size; i++) {
		if ((old->bytes->bytes[i] & old->bytes->mask[i]) != (new->bytes->bytes[i] & new->bytes->mask[i])) {
			eprintf("Masked bytes mismatch\n");
			return false;
		}
	}
	return true;
}

static bool loadCB(void *user, const char *k, const char *v) {
	RzAnalysis *a = (RzAnalysis *)user;
	RzSignItem *it = rz_sign_item_new();
	if (it && rz_sign_deserialize(a, it, k, v)) {
		if (!ht_pp_insert(a->zigns_ht, it, it)) {
			RzSignItem *cur = ht_pp_find(a->zigns_ht, it, NULL);
			if (!debug_cmp_sign_bytes(cur, it)) {
				eprintf("error: new sign %s with different bytes\n", it->name);
			}
		}
	} else {
		rz_sign_item_free(it);
		eprintf("error: cannot deserialize zign\n");
	}
	return true;
}

RZ_API char *rz_sign_path(RzAnalysis *a, const char *file) {
	char *abs = rz_file_abspath(file);
	if (abs) {
		if (rz_file_is_regular(abs)) {
			return abs;
		}
		free(abs);
	}

	if (a->zign_path) {
		char *path = rz_str_newf("%s%s%s", a->zign_path, RZ_SYS_DIR, file);
		abs = rz_file_abspath(path);
		free(path);
		if (rz_file_is_regular(abs)) {
			return abs;
		}
		free(abs);
	} else {
		char *home = rz_str_home(RZ_HOME_ZIGNS);
		abs = rz_str_newf("%s%s%s", home, RZ_SYS_DIR, file);
		free(home);
		if (rz_file_is_regular(abs)) {
			return abs;
		}
		free(abs);
	}

	abs = rz_str_newf(RZ_JOIN_3_PATHS("%s", RZ_ZIGNS, "%s"), rz_sys_prefix(NULL), file);
	if (rz_file_is_regular(abs)) {
		return abs;
	}
	free(abs);

	return NULL;
}

RZ_API bool rz_sign_load(RzAnalysis *a, const char *file) {
	if (!a || !file) {
		return false;
	}
	char *path = rz_sign_path(a, file);
	if (!rz_file_exists(path)) {
		eprintf("error: file %s does not exist\n", file);
		free(path);
		return false;
	}
	Sdb *db = sdb_new(NULL, path, 0);
	if (!db) {
		free(path);
		return false;
	}
	sdb_foreach(db, loadCB, a);
	sdb_close(db);
	sdb_free(db);
	free(path);
	return true;
}

RZ_API bool rz_sign_load_gz(RzAnalysis *a, const char *filename) {
	ut8 *buf = NULL;
	int size = 0;
	char *tmpfile = NULL;
	bool retval = true;

	char *path = rz_sign_path(a, filename);
	if (!rz_file_exists(path)) {
		eprintf("error: file %s does not exist\n", filename);
		retval = false;
		goto out;
	}

	if (!(buf = rz_file_gzslurp(path, &size, 0))) {
		eprintf("error: cannot decompress file\n");
		retval = false;
		goto out;
	}

	if (!(tmpfile = rz_file_temp("r2zign"))) {
		eprintf("error: cannot create temp file\n");
		retval = false;
		goto out;
	}

	if (!rz_file_dump(tmpfile, buf, size, 0)) {
		eprintf("error: cannot dump file\n");
		retval = false;
		goto out;
	}

	if (!rz_sign_load(a, tmpfile)) {
		eprintf("error: cannot load file\n");
		retval = false;
		goto out;
	}

	if (!rz_file_rm(tmpfile)) {
		eprintf("error: cannot delete temp file\n");
		retval = false;
		goto out;
	}

out:
	free(buf);
	free(tmpfile);
	free(path);

	return retval;
}

typedef struct serialize_ctx {
	Sdb *db;
	const char *filename;
	ut32 path_hash;	
} SerializeCtx;

//R_IPI rz_sign_to_json(RzSignItem *it, )

bool serialize_cb(void *user, const char *k, void *v) {
	SerializeCtx *ctx = (SerializeCtx *)user;
	RzSignItem *it = (RzSignItem *)v;
	const char *spacename = rz_sign_space_name(it);
	char *key[SDB_KSZ];
	// Not reproducable from anot
	snprintf(key, sizeof(key), "%08x%08x%08x|%s",
			ctx->path_hash, sdb_hash(spacename), sdb_hash(it->realname), it->name);
	PJ *pj = pj_new();
	if (pj) {
		pj_o(pj);
		if (ctx->filename) {
			pj_ks(pj, "origin", ctx->filename); // FOR DEBUG PURPOSE
		}
		pj_ks(pj, "name", it->name);
		pj_ks(pj, "space", spacename);
		if (it->realname) {
			pj_ks(pj, "realname", it->realname);
		}
		if (it->bytes) {
			pj_k(pj, "bytes");
			pj_o(pj);
			pj_kn(pj, "size", it->bytes->size);
			char *hex_bytes = rz_hex_bin2strdup(it->bytes->bytes, it->bytes->size);
			char *hex_mask = rz_hex_bin2strdup(it->bytes->mask, it->bytes->size);
			pj_ks(pj, "bytes", hex_bytes);
			pj_ks(pj, "mask", hex_mask);
			pj_end(pj);
		}
		if (it->refs && !rz_list_empty(it->refs)) {
			pj_k(pj, "refs");
			pj_a(pj);
			RzListIter *i;
			RzSignXrefInfo *r;
			rz_list_foreach (it->refs, i, r) {
				pj_o(pj);
				pj_kn(pj, "size", r->size);
				pj_kN(pj, "offset", r->offset);
				pj_ks(pj, "name", r->name);
				pj_end(pj);
			}
			pj_end(pj);
		}
		if (it->inner_refs && !rz_list_empty(it->inner_refs)) {
			pj_k(pj, "irefs");
			pj_a(pj);
			RzListIter *i;
			RzSignInnerXref *r;
			rz_list_foreach (it->inner_refs, i, r) {
				pj_o(pj);
				pj_kN(pj, "src_offset", r->src_offset);
				pj_kN(pj, "dst_offset", r->dst_offset);
				pj_end(pj);
			}
			pj_end(pj);
		}

		pj_end(pj);

		sdb_set_owned(ctx->db, key, pj_drain (pj), 0);
	}
	return true;
}

RZ_API bool rz_sign_save(RzAnalysis *a, const char *file) {
	rz_return_val_if_fail(a && file, false);
	Sdb *db = sdb_new(NULL, file, 0);
	if (!db) {
		return false;
	}
	SerializeCtx ctx;
	const char *path = a->coreb.cfgGet((RzCore *)(a->coreb.core), "file.path");
	const char *f = strrchr(path, RZ_SYS_DIR[0]);
	ctx.filename = f? (f + 1): NULL;
	ctx.db = db;
	ctx.path_hash = sdb_hash(path);
	ht_pp_foreach(a->zigns_ht, serialize_cb, &ctx);

	bool retval = sdb_sync(db);
	sdb_close(db);
	sdb_free(db);

	return retval;
}

RZ_API RzSignOptions *rz_sign_options_new(const char *bytes_thresh, const char *graph_thresh) {
	RzSignOptions *options = RZ_NEW0(RzSignOptions);
	if (!options) {
		return NULL;
	}

	options->bytes_diff_threshold = rz_num_get_float(NULL, bytes_thresh);
	options->graph_diff_threshold = rz_num_get_float(NULL, graph_thresh);

	if (options->bytes_diff_threshold > 1.0) {
		options->bytes_diff_threshold = 1.0;
	}
	if (options->bytes_diff_threshold < 0) {
		options->bytes_diff_threshold = 0.0;
	}
	if (options->graph_diff_threshold > 1.0) {
		options->graph_diff_threshold = 1.0;
	}
	if (options->graph_diff_threshold < 0) {
		options->graph_diff_threshold = 0.0;
	}

	return options;
}

RZ_API void rz_sign_options_free(RzSignOptions *options) {
	RZ_FREE(options);
}
