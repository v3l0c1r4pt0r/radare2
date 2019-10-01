/* radare - LGPL - Copyright 2019 - pancake */

#include <r_anal.h>

#define D if (anal->verbose)

R_API void r_anal_function_ref (RAnalFunction *fcn) {
	fcn->ref++;
}

R_API const RList *r_anal_get_functions(RAnal *anal, ut64 addr) {
	RAnalBlock *bb = r_anal_get_block (anal, addr);
	return bb? bb->fcns: NULL;
}

R_API RAnalFunction *r_anal_add_function(RAnal *anal, const char *name, ut64 addr) {
	RAnalFunction *fcn = r_anal_fcn_new (anal);
	if (fcn) {
		free (fcn->name);
		if (name) {
			fcn->name = strdup (name);
		}
		r_anal_function_ref (fcn);
		r_list_append (anal->fcns, fcn);
	}
	return fcn;
}

R_API void r_anal_function_add_block(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb) {
	if (!r_anal_add_block (anal, bb)) { // register basic block globally
		D eprintf ("Theres a block %llx vs %llx\n", fcn->addr, bb->addr);
	}
	D eprintf ("add bl\n");
	r_anal_function_ref (fcn);
	r_list_append (bb->fcns, fcn); // associate the given fcn with this bb
	r_anal_block_ref (bb);
	r_list_append (fcn->bbs, bb); // TODO: avoid double insert the same bb
	if (anal->cb.on_fcn_bb_new) {
		anal->cb.on_fcn_bb_new (anal, anal->user, fcn, bb);
	}
//	eprintf ("Cannot add block., already there\n");
}

R_API void r_anal_function_del_block(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb) {
	r_list_delete_data (bb->fcns, fcn);
	r_list_delete_data (fcn->bbs, bb);
	(void)r_anal_del_block (anal, bb); // TODO: honor unref
}

R_API void r_anal_function_unref(RAnalFunction *fcn) {
	RAnal *anal = fcn->anal;
	D eprintf ("unref fun %d 0x%llx\n", fcn->ref, fcn->addr);
	fcn->ref--;
	D eprintf ("unref2 eliminating %d bbs\n", r_list_length (fcn->bbs));
	D eprintf ("unref2 fun %d\n", fcn->ref);
	if (fcn->ref < 1) {
		r_anal_del_function (fcn);
	}
}

R_API bool r_anal_del_function(RAnalFunction *fcn) {
	RAnal *anal = fcn->anal;
	D eprintf ("del fun\n");
	if (!r_anal_fcn_tree_delete (anal, fcn)) {
		return false;
	}
	RListIter *iter, *iter2;
	RAnalBlock *bb;
	r_list_foreach_safe (fcn->bbs, iter, iter2, bb) {
		r_list_free (bb->fcns);
		//r_anal_block_unref (bb);
		r_list_delete (fcn->bbs, iter);
	}
	//r_list_delete (a->fcns, iter);
	r_list_delete_data (anal->fcns, fcn);
	ht_up_delete (anal->ht_bbs, fcn->addr);
	D eprintf ("delete data\n");
	r_anal_fcn_free (fcn);
	r_list_free (fcn->bbs);
	r_anal_fcn_tree_delete (anal, fcn);
	return true;
}
