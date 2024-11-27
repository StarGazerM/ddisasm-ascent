use ascent::ascent;
use std::borrow::Borrow;
use itertools::Itertools;


fn read_csv<T>(path: &str) -> impl Iterator<Item = T>
where
   for<'de> T: serde::de::Deserialize<'de>,
{
   csv::ReaderBuilder::new()
      .delimiter(b'\t')
      .has_headers(false)
      .double_quote(false)
      .quoting(false)
      .from_path(path)
      .unwrap()
      .into_deserialize()
      .map(|x| x.unwrap())
}


fn leak<T: Borrow<TB> + 'static, TB: ?Sized>(x: T) -> &'static TB {
    let leaked: &'static T = Box::leak(Box::new(x));
    leaked.borrow()
 }

type InputReg=String;
type RegNullable=String;
type Register=String;
type Address=u64;
type OperandCode=u64;
type OperandIndex=u64;

type LimitType=String;
type BlockType=String;

type AccessMode=String;
type SymbolPosition=String;

type StackVar=(Register, u64);
type ConditionCode=String;


ascent! {

    relation value_reg(Address, Register, Address, RegNullable, i64, i64, u64);
    relation base_relative_jump(Address, Address);
    relation base_relative_operand(Address, OperandIndex, Address);
    relation block_next(Address, Address, Address);
    relation cmp_defines(Address, Address, Register);
    relation compare_and_jump_immediate(Address, Address, ConditionCode, Register, i64);
    relation compare_and_jump_indirect(Address, Address, ConditionCode, OperandCode, i64);
    relation compare_and_jump_register(Address, Address, ConditionCode, Register, Register);
    relation const_value_reg_used(Address, Address, Address, Register, i64);
    relation def_used_for_address(Address, Register, SymbolPosition);
    relation flags_and_jump_pair(Address, Address, ConditionCode);
    relation got_relative_operand(Address, OperandIndex, Address);
    relation jump_table_element_access(Address, u64, Address, Register);
    relation jump_table_max(Address, Address);
    relation jump_table_signed(Address, u64);
    relation jump_table_start(Address, u64, Address, Address, i64);
    relation jump_table_target(Address, Address);
    relation last_value_reg_limit(Address, Address, Register, i64, LimitType, u64);
    relation reg_def_use_def_used(Address, Register, Address, OperandIndex);
    relation reg_def_use_live_var_at_block_end(Address, Address, Register);
    relation reg_def_use_live_var_at_prior_used(Address, Address, Register);
    relation reg_def_use_live_var_used(Address, Register, Register, Address, OperandIndex, u64);
    relation reg_def_use_return_val_used(Address, Address, Register, Address, OperandIndex);
    relation reg_has_base_image(Address, Register);
    relation reg_has_got(Address, Register);
    relation reg_reg_arithmetic_operation_defs(Address, Register, Address, Register, Address, Register, i64, i64);
    relation relative_jump_table_entry_candidate(Address, Address, u64, Address, Address, i64, i64);
    relation stack_def_use_def_used(Address, StackVar, Address, StackVar, OperandIndex);
    relation stack_def_use_live_var_at_block_end(Address, Address, StackVar);
    relation stack_def_use_live_var_at_prior_used(Address, Address, StackVar);
    relation stack_def_use_live_var_used(Address, StackVar, StackVar, Address, OperandIndex, u64);
    relation stack_def_use_live_var_used_in_block(Address, Address, StackVar, StackVar, Address, OperandIndex, u64);
    relation tls_desc_call(Address, Address, Address);
    relation tls_get_addr(Address, Address, Address);
    relation value_reg_edge(Address, Register, Address, Register, i64, i64);
    relation value_reg_limit(Address, Address, Register, i64, LimitType);
    relation value_reg_unsupported(Address, Register);
    relation adjusts_stack_in_block(Address, Address, Register, i64);
    relation after_end(Address, Address);
    relation arch_call(Address, OperandIndex);
    relation arch_cmp_operation(String);
    // .decl arch_cmp_zero_operation(Operation:symbol)
    relation arch_cmp_zero_operation(String);

    // .decl arch_condition_flags_reg(Reg:register)
    relation arch_condition_flags_reg(Register);
    
    relation arch_condition_flags_reg(Register);

    // .decl arch_conditional(EA:address,CC:condition_code)
    relation arch_conditional(Address, ConditionCode);

    // .decl arch_extend_load(EA:address,Signed:unsigned,SrcBits:unsigned)
    relation arch_extend_load(Address, Register, u64, u64);

    // .decl arch_extend_reg(EA:address,Reg:register,Signed:unsigned,SrcBits:unsigned)
    relation arch_extend_reg(Address, Register, Register, u64, u64);

    // .decl arch_jump(EA:address)
    relation arch_jump(Address);

    // decl arch_memory_access(AccessType:symbol,EA:address,SrcOp:operand_index,DstOp:operand_index,
    //     DirectReg:register,BaseReg:reg_nullable,IndexReg:reg_nullable,Mult:number,Offset:number)
    relation arch_memory_access(AccessMode, Address, OperandIndex, OperandIndex, Register, RegNullable, RegNullable, i64, i64);
    
    // .decl arch_move_reg_imm(EA:address,Dst:register,Imm:number,ImmIndex:operand_index)
    relation arch_move_reg_imm(Address, Register, i64, OperandIndex);

    // .decl arch_move_reg_reg(EA:address,Dst:register,Src:register)
    relation arch_move_reg_reg(Address, Register, Register);

    // .decl arch_pc_relative_addr(EA:address,Reg:register,Target:address)
    relation arch_pc_relative_addr(Address, Register, Address);

    // .decl arch_reg_arithmetic_operation(EA:address,Dst:register,Src:register,Mult:number,Offset:number)
    relation arch_reg_arithmetic_operation(Address, Register, Register, i64, i64);

    // .decl arch_reg_reg_arithmetic_operation(EA:address,Dst:register,Src1:register,Src2:register,Mult:number,Offset:number)
    relation arch_reg_reg_arithmetic_operation(Address, Register, Register, Register, i64, i64);

    // .decl arch_register_size_bytes(Reg:input_reg,Size:unsigned)
    relation arch_register_size_bytes(InputReg, u64);

    // .decl arch_return_reg(Reg:register)
    relation arch_return_reg(Register);

    // .decl arch_stack_pointer(Reg:register)
    relation arch_stack_pointer(Register);

    // .decl arch_store_immediate(EA:address,SrcOp:operand_index,DstOp:operand_index,
    //     Immediate:number,BaseReg:reg_nullable,IndexReg:reg_nullable,Mult:number,Offset:number)
    relation arch_store_immediate(Address, OperandIndex, OperandIndex, i64, RegNullable, RegNullable, i64, i64);

    // .decl base_address(ea:address)
    relation base_address(Address);

    // .decl base_relative_operation(EA_relop:address,EA:address)
    relation base_relative_operation(Address, Address);

    // .decl binary_format(Format:symbol)
    relation binary_format(String);

    // .decl block(Block:address)
    relation block(Address);

    // .decl call_tls_get_addr(Call:address,Reg:register)
    // .decl cmp_immediate_to_reg(EA:address,Reg:register,Imm_index:operand_index,Immediate:number)
    // .decl cmp_reg_to_reg(EA:address,Reg1:register,Reg2:register)
    // .decl code_in_block(EA:address,Block:address)
    // .decl conditional_jump(src:address)
    // .decl data_access(EA:address,Op_index:operand_index,RegSegment:reg_nullable,RegBase:reg_nullable,RegIndex:reg_nullable,Mult:number,Offset:number,Size:unsigned)
    // .decl data_segment(Begin:address,End:address)
    // .decl defined_symbol(ea:address,size:unsigned,type:symbol,scope:symbol,visibility:symbol,sectionIndex:unsigned,originTable:symbol,tableIndex:unsigned,name:symbol)
    // .decl direct_call(EA:address,Dest:address)
    // .decl direct_jump(src:address, dest:address)
    // .decl got_reference_pointer(EA:address)
    // .decl got_section(name:symbol)
    // .decl instruction(ea:address,size:unsigned,prefix:symbol,opcode:symbol,
    //           op1:operand_code,op2:operand_code,op3:operand_code,op4:operand_code,
    //           immOffset:unsigned,displacementOffset:unsigned)
    // .decl instruction_displacement_offset(EA:address,Index:operand_index,Offset:unsigned,Size:unsigned)
    // .decl instruction_get_dest_op(EA:address,Index:operand_index,Op:operand_code)
    // .decl instruction_get_op(ea:address, index:operand_index, operator:operand_code)
    // .decl instruction_get_src_op(EA:address,Index:operand_index,Op:operand_code)
    // .decl instruction_has_relocation(EA:address,Rel:address)
    // .decl inter_procedural_edge(Src:address,Dest:address)
    // .decl is_padding(EA:address)
    // .decl is_xor_reset(EA:address)
    // .decl limit_reg_op(EA:address,DstReg:register,SrcReg:register,Offset:number)
    // .decl limit_type_map(CC:condition_code,BranchLT:limit_type,FallthroughLT:limit_type,BranchOffset:number,FallthroughOffset:number)
    // .decl loaded_section(Beg:address,End:address,Name:symbol)
    // .decl lsda_callsite_addresses(Start:address,End:address,LandingPad:address)
    // .decl may_fallthrough(o:address,d:address)
    // .decl next(n:address,m:address)
    // .decl no_return_call_propagated(EA:address)
    // .decl block_instruction_next(Block:address,Before:address,After:address)
    // .decl block_last_instruction(Block:address,EA:address)

    relation block_instruction_next(Address, Address, Address);
    relation block_last_instruction(Address, Address);
    relation call_tls_get_addr(Address, Register);
    relation cmp_immediate_to_reg(Address, Register, OperandIndex, i64);
    relation cmp_reg_to_reg(Address, Register, Register);
    relation code_in_block(Address, Address);
    relation conditional_jump(Address);
    relation data_access(Address, OperandIndex, RegNullable, RegNullable, RegNullable, i64, i64, u64);
    relation data_segment(Address, Address);
    relation defined_symbol(Address, u64, String, String, String, u64, String, u64, String);
    relation direct_call(Address, Address);
    relation direct_jump(Address, Address);
    relation got_reference_pointer(Address);
    relation got_section(String);
    relation instruction(Address, u64, String, String, OperandCode, OperandCode, OperandCode, OperandCode, u64, u64);
    relation instruction_displacement_offset(Address, OperandIndex, u64, u64);
    relation instruction_get_dest_op(Address, OperandIndex, OperandCode);
    relation instruction_get_op(Address, OperandIndex, OperandCode);
    relation instruction_get_src_op(Address, OperandIndex, OperandCode);
    relation instruction_has_relocation(Address, Address);
    relation inter_procedural_edge(Address, Address);
    relation is_padding(Address);
    relation is_xor_reset(Address);
    relation limit_reg_op(Address, Register, Register, i64);
    relation limit_type_map(ConditionCode, LimitType, LimitType, i64, i64);
    relation loaded_section(Address, Address, String);
    relation lsda_callsite_addresses(Address, Address, Address);
    relation may_fallthrough(Address, Address);
    relation next(Address, Address);
    relation no_return_call_propagated(Address);

    // .decl no_value_reg_limit(EA_jmp:address)
    // .decl op_immediate(Code:operand_code,Offset:number,SizeBytes:unsigned)
    // .decl op_immediate_and_reg(EA:address,Operation:symbol,Reg:register,Imm_index:operand_index,Immediate:number)
    // .decl op_indirect(Code:operand_code,Reg1:input_reg,Reg2:input_reg,Reg3:input_reg,
    //         Multiplier:number,Offset:number,SizeBytes:unsigned)
    // .decl op_indirect_mapped(Op:operand_code,Reg1:reg_nullable,Reg2:reg_nullable,Reg3:reg_nullable,Mult:number,Offset:number,Size:unsigned)
    // .decl op_regdirect(Code:operand_code,RegisterName:input_reg)
    // .decl op_regdirect_contains_reg(Op:operand_code,Reg:register)
    // .decl pc_relative_operand(src:address,index:operand_index, dest:address)
    // .decl possible_rva_operand(EA:address,Index:operand_index,Dest:address)
    // .decl reg_call(Src:address,Reg:register)
    // .decl reg_def_use_block_last_def(EA:address,EA_def:address,Var:register)
    // .decl reg_def_use_def(EA:address,Var:register)
    // // .decl reg_def_use_def_used(EA_def:address,Var:register,EA_used:address,Index_used:operand_index)
    // // .input reg_def_use_def_used(filename="reg_def_use.def_used.facts")
    // .decl reg_def_use_defined_in_block(Block:address,Var:register)
    // .decl reg_def_use_flow_def(EA:address,Var:register,EA_next:address,Value:number)
    // .decl reg_def_use_live_var_def(Block:address,VarIdentity:register,LiveVar:register,EA_def:address)
    // .decl reg_def_use_ref_in_block(Block:address,Var:register)
    relation no_value_reg_limit(Address);
    relation op_immediate(OperandCode, i64, u64);
    relation op_immediate_and_reg(Address, String, Register, OperandIndex, i64);
    relation op_indirect(OperandCode, InputReg, InputReg, InputReg, i64, i64, u64);
    relation op_indirect_mapped(OperandCode, RegNullable, RegNullable, RegNullable, i64, i64, u64);
    relation op_regdirect(OperandCode, InputReg);
    relation op_regdirect_contains_reg(OperandCode, Register);
    relation pc_relative_operand(Address, OperandIndex, Address);
    relation possible_rva_operand(Address, OperandIndex, Address);
    relation reg_call(Address, Register);
    relation reg_def_use_block_last_def(Address, Address, Register);
    relation reg_def_use_def(Address, Register);
    relation reg_def_use_defined_in_block(Address, Register);
    relation reg_def_use_flow_def(Address, Register, Address, i64);
    relation reg_def_use_live_var_def(Address, Register, Register, Address);
    relation reg_def_use_ref_in_block(Address, Register);

    // .decl reg_def_use_return_block_end(Callee:address,CalleeEnd:address,Block:address,BlockEnd:address)
    // .decl reg_def_use_used(EA:address,Var:register,Index:operand_index)
    // .decl reg_def_use_used_in_block(Block:address,EA_used:address,Var:register,Index:operand_index)
    // .decl reg_jump(Src:address,Reg:register)
    // .decl reg_map(RegIn:input_reg,Reg:register)
    // .decl reg_used_for(EA:address,Reg:register,Type:symbol)
    // .decl register_access(EA:address,Register:input_reg,AccessMode:access_mode)
    // .decl relative_address(EA:address,Size:unsigned,TableStart:address,Reference:address,Dest:address,DestIsFirstOrSecond:symbol)
    // .decl relative_address_start(EA:address,Size:unsigned,Reference:address,Dest:address, DestIsFirstOrSecond:symbol)
    // .decl relocation(EA:address,Type:symbol,Name:symbol,Addend:number,SymbolIndex:unsigned,Section:symbol,RelType:symbol)
    // .decl relocation_adjustment_total(EA:address,Adjustment:number)
    // .decl simple_data_access_pattern(Address:address,Op_index:unsigned,Size:unsigned,FromWhere:address)
    // .decl stack_base_reg_move(Block:address,EA:address,Src:register,Dst:register)
    // .decl stack_def_use_block_last_def(EA:address,EA_def:address,Var:stack_var)
    // .decl stack_def_use_def(EA:address,Var:stack_var)
    // .decl stack_def_use_defined_in_block(Block:address,Var:stack_var)
    // .decl stack_def_use_live_var_def(Block:address,VarIdentity:stack_var,LiveVar:stack_var,EA_def:address)
    // .decl stack_def_use_moves_limit(Moves:unsigned)
    // .decl stack_def_use_ref_in_block(Block:address,Var:stack_var)
    // .decl stack_def_use_used(EA:address,Var:stack_var,Index:operand_index)
    // .decl stack_def_use_used_in_block(Block:address,EA_used:address,Var:stack_var,Index:operand_index)
    // .decl step_limit(Limit:unsigned)
    // .decl step_limit_small(Limit:unsigned)
    // .decl symbol(ea:address,size:unsigned,type:symbol,scope:symbol,visibility:symbol,sectionIndex:unsigned,originTable:symbol,tableIndex:unsigned,name:symbol)
    // .decl symbolic_expr_from_relocation(EA:address,Size:unsigned,Symbol:symbol,Offset:number,TargetEA:address)
    // .decl take_address(Src:address,Address_taken:address)
    // .decl tls_descriptor(EA:address,Offset:unsigned)
    // .decl tls_index(EA:address,Offset:unsigned)
    // .decl tls_segment(Start:address,End:address,Align:unsigned)
    // .decl track_register(Reg:register)
    relation reg_def_use_return_block_end(Address, Address, Address, Address);
    relation reg_def_use_used(Address, Register, OperandIndex);
    relation reg_def_use_used_in_block(Address, Address, Register, OperandIndex);
    relation reg_jump(Address, Register);
    relation reg_map(InputReg, Register);
    relation reg_used_for(Address, Register, String);
    relation register_access(Address, InputReg, AccessMode);
    relation relative_address(Address, u64, Address, Address, Address, String);
    relation relative_address_start(Address, u64, Address, Address, String);
    relation relocation(Address, String, String, i64, u64, String, String);
    relation relocation_adjustment_total(Address, i64);
    relation simple_data_access_pattern(Address, u64, u64, Address);
    relation stack_base_reg_move(Address, Address, Register, Register);
    relation stack_def_use_block_last_def(Address, Address, StackVar);
    relation stack_def_use_def(Address, StackVar);
    relation stack_def_use_defined_in_block(Address, StackVar);
    relation stack_def_use_live_var_def(Address, StackVar, StackVar, Address);
    relation stack_def_use_moves_limit(u64);
    relation stack_def_use_ref_in_block(Address, StackVar);
    relation stack_def_use_used(Address, StackVar, OperandIndex);
    relation stack_def_use_used_in_block(Address, Address, StackVar, OperandIndex);
    relation step_limit(u64);
    relation step_limit_small(u64);
    relation symbol(Address, u64, String, String, String, u64, String, u64, String);
    relation symbolic_expr_from_relocation(Address, u64, String, i64, Address);
    relation take_address(Address, Address);
    relation tls_descriptor(Address, u64);
    relation tls_index(Address, u64);
    relation tls_segment(Address, Address, u64);
    relation track_register(Register);

    // block_next(Block,EA,Block2) :- 
    // block_last_instruction(Block,EA),
    // may_fallthrough(EA,Block2),
    // !no_return_call_propagated(EA),
    // !inter_procedural_edge(EA,Block2),
    // block(Block2).

    block(Block, EA, Block2) <-- 
        block_last_instruction(Block, EA),
        may_fallthrough(EA, Block2), 
        // agg () = not() no_return_call_propagated(EA), 
        agg () = not() inter_procedural_edge(EA, Block2),
        block(Block2);

    // block_next(Block,EA,Block2) :- 
    //     lsda_callsite_addresses(Beg,End,Block2),
    //     block_last_instruction(Block,EA),
    //     EA >= Beg,
    //     EA < End,
    //     block(Block2).
    // block_next(Block, EA, Block2) <-- 
    //     lsda_callsite_addresses(Beg, End, Block2),
    //     block_last_instruction(Block, EA),
    //     if EA >= Beg,
    //     if EA < End,
    //     block(Block2);
    // value_reg(EALoad,Reg2,EALoad,"NONE",0,Immediate,1) :- 
    // arch_store_immediate(EAStore,_,_,Immediate,RegBaseStore,"NONE",_,StackPosStore),
    // stack_def_use_def_used(EAStore,[RegBaseStore,StackPosStore],EALoad,[RegBaseLoad,StackPosLoad],_),
    // arch_memory_access("LOAD",EALoad,_,_,Reg2,RegBaseLoad,inlined_IndexReg_452,_,StackPosLoad),
    // inlined_IndexReg_452 = "NONE",
    // def_used_for_address(EALoad,Reg2,_).

    // value_reg(EALoad, Reg2, EALoad, "NONE", 0, Immediate, 1) <-
    //     arch_store_immediate(EAStore, _, _, Immediate, RegBaseStore, "NONE", _, StackPosStore),
    //     stack_def_use_def_used(EAStore, (RegBaseStore, StackPosStore), EALoad, [RegBaseLoad, StackPosLoad], _),
    //     arch_memory_access("LOAD", EALoad, _, _, Reg2, RegBaseLoad, inlined_IndexReg_452, _, StackPosLoad),
    //     let inlined_IndexReg_452 = "NONE",
    //     def_used_for_address(EALoad, Reg2, _);



 }

fn main() {
    let mut program = AscentProgram::default();
    let value_reg_size = program.value_reg.len();
    println!("value_reg size: {:?}", value_reg_size);
    let base_relative_jump_size = program.base_relative_jump.len();
    println!("base_relative_jump size: {:?}", base_relative_jump_size);
    let base_relative_operand_size = program.base_relative_operand.len();
    println!("base_relative_operand size: {:?}", base_relative_operand_size);
    let block_next_size = program.block_next.len();
    println!("block_next size: {:?}", block_next_size);
    let cmp_defines_size = program.cmp_defines.len();
    println!("cmp_defines size: {:?}", cmp_defines_size);
    let compare_and_jump_immediate_size = program.compare_and_jump_immediate.len();
    println!("compare_and_jump_immediate size: {:?}", compare_and_jump_immediate_size);
    let compare_and_jump_indirect_size = program.compare_and_jump_indirect.len();
    println!("compare_and_jump_indirect size: {:?}", compare_and_jump_indirect_size);
    let compare_and_jump_register_size = program.compare_and_jump_register.len();
    println!("compare_and_jump_register size: {:?}", compare_and_jump_register_size);
    let const_value_reg_used_size = program.const_value_reg_used.len();
    println!("const_value_reg_used size: {:?}", const_value_reg_used_size);
    let def_used_for_address_size = program.def_used_for_address.len();
    println!("def_used_for_address size: {:?}", def_used_for_address_size);
    let flags_and_jump_pair_size = program.flags_and_jump_pair.len();
    println!("flags_and_jump_pair size: {:?}", flags_and_jump_pair_size);
    let got_relative_operand_size = program.got_relative_operand.len();
    println!("got_relative_operand size: {:?}", got_relative_operand_size);
    let jump_table_element_access_size = program.jump_table_element_access.len();
    println!("jump_table_element_access size: {:?}", jump_table_element_access_size);
    let jump_table_max_size = program.jump_table_max.len();
    println!("jump_table_max size: {:?}", jump_table_max_size);
    let jump_table_signed_size = program.jump_table_signed.len();
    println!("jump_table_signed size: {:?}", jump_table_signed_size);
    let jump_table_start_size = program.jump_table_start.len();
    println!("jump_table_start size: {:?}", jump_table_start_size);
    let jump_table_target_size = program.jump_table_target.len();
    println!("jump_table_target size: {:?}", jump_table_target_size);
    let last_value_reg_limit_size = program.last_value_reg_limit.len();
    println!("last_value_reg_limit size: {:?}", last_value_reg_limit_size);
    let reg_def_use_def_used_size = program.reg_def_use_def_used.len();
    println!("reg_def_use_def_used size: {:?}", reg_def_use_def_used_size);
    let reg_def_use_live_var_at_block_end_size = program.reg_def_use_live_var_at_block_end.len();
    println!("reg_def_use_live_var_at_block_end size: {:?}", reg_def_use_live_var_at_block_end_size);
    let reg_def_use_live_var_at_prior_used_size = program.reg_def_use_live_var_at_prior_used.len();
    println!("reg_def_use_live_var_at_prior_used size: {:?}", reg_def_use_live_var_at_prior_used_size);
    let reg_def_use_live_var_used_size = program.reg_def_use_live_var_used.len();
    println!("reg_def_use_live_var_used size: {:?}", reg_def_use_live_var_used_size);
    let reg_def_use_return_val_used_size = program.reg_def_use_return_val_used.len();
    println!("reg_def_use_return_val_used size: {:?}", reg_def_use_return_val_used_size);
    let reg_has_base_image_size = program.reg_has_base_image.len();
    println!("reg_has_base_image size: {:?}", reg_has_base_image_size);
    let reg_has_got_size = program.reg_has_got.len();
    println!("reg_has_got size: {:?}", reg_has_got_size);
    let reg_reg_arithmetic_operation_defs_size = program.reg_reg_arithmetic_operation_defs.len();
    println!("reg_reg_arithmetic_operation_defs size: {:?}", reg_reg_arithmetic_operation_defs_size);
    let relative_jump_table_entry_candidate_size = program.relative_jump_table_entry_candidate.len();
    println!("relative_jump_table_entry_candidate size: {:?}", relative_jump_table_entry_candidate_size);
    let stack_def_use_def_used_size = program.stack_def_use_def_used.len();
    println!("stack_def_use_def_used size: {:?}", stack_def_use_def_used_size);
    let stack_def_use_live_var_at_block_end_size = program.stack_def_use_live_var_at_block_end.len();
    println!("stack_def_use_live_var_at_block_end size: {:?}", stack_def_use_live_var_at_block_end_size);
    let stack_def_use_live_var_at_prior_used_size = program.stack_def_use_live_var_at_prior_used.len();
    println!("stack_def_use_live_var_at_prior_used size: {:?}", stack_def_use_live_var_at_prior_used_size);
    let stack_def_use_live_var_used_size = program.stack_def_use_live_var_used.len();
    println!("stack_def_use_live_var_used size: {:?}", stack_def_use_live_var_used_size);
    let stack_def_use_live_var_used_in_block_size = program.stack_def_use_live_var_used_in_block.len();
    println!("stack_def_use_live_var_used_in_block size: {:?}", stack_def_use_live_var_used_in_block_size);
    let tls_desc_call_size = program.tls_desc_call.len();
    println!("tls_desc_call size: {:?}", tls_desc_call_size);
    let tls_get_addr_size = program.tls_get_addr.len();
    println!("tls_get_addr size: {:?}", tls_get_addr_size);
    let value_reg_edge_size = program.value_reg_edge.len();
    println!("value_reg_edge size: {:?}", value_reg_edge_size);
    let value_reg_limit_size = program.value_reg_limit.len();
    println!("value_reg_limit size: {:?}", value_reg_limit_size);
    let value_reg_unsupported_size = program.value_reg_unsupported.len();
    println!("value_reg_unsupported size: {:?}", value_reg_unsupported_size);    

    let path = "./data/";
    let get_path = |x: &str| format!("{path}{x}");

    program.adjusts_stack_in_block = read_csv::<(Address, Address, Register, i64)>(&get_path("adjusts_stack_in_block.facts"))
        .map(|(x, y, z, xx)| (x, y, z, xx))
        .collect_vec();
    program.after_end = read_csv::<(Address, Address)>(&get_path("after_end.facts"))
        .map(|(x, y)| (x, y))
        .collect_vec();

    // Attention on the path
    program.arch_call = read_csv::<(Address, OperandIndex)>(&get_path("arch.call.facts"))
        .map(|(x, y)| (x, y))
        .collect_vec();

    // .input arch_cmp_operation(filename="arch.cmp_operation.facts")
    program.arch_cmp_operation = read_csv::<(String,)>(&get_path("arch.cmp_operation.facts"))
        .map(|(x,)| (x,))
        .collect_vec();


    // .input arch_cmp_zero_operation(filename="arch.cmp_zero_operation.facts")
    program.arch_cmp_zero_operation = read_csv::<(String,)>(&get_path("arch.cmp_zero_operation.facts"))
        .map(|(x,)| (x,))
        .collect_vec();

    // arch_cmp_zero_operation(""):-
    //     false.
    // Todo

    // .input arch_conditional(filename="arch.conditional.facts")
    program.arch_conditional = read_csv::<(Address, ConditionCode)>(&get_path("arch.conditional.facts"))
        .map(|(x, y)| (x, y))
        .collect_vec();

    // .input arch_condition_flags_reg(filename="arch.condition_flags_reg.facts")
    program.arch_condition_flags_reg = read_csv::<(Register,)>(&get_path("arch.condition_flags_reg.facts"))
        .map(|(x,)| (x,))
        .collect_vec();

    // .input arch_extend_load(filename="arch.extend_load.facts")
    program.arch_extend_load = read_csv::<(Address, Register, u64, u64)>(&get_path("arch.extend_load.facts"))
        .map(|(x, y, z, xx)| (x, y, z, xx))
        .collect_vec();

    // .input arch_extend_reg(filename="arch.extend_reg.facts")
    program.arch_extend_reg = read_csv::<(Address, Register, Register, u64, u64)>(&get_path("arch.extend_reg.facts"))
        .map(|(x, y, z, xx, xxx)| (x, y, z, xx, xxx))
        .collect_vec();

    // .input arch_jump(filename="arch.jump.facts")
    program.arch_jump = read_csv::<(Address,)>(&get_path("arch.jump.facts"))
        .map(|(x,)| (x,))
        .collect_vec();

    // .input arch_memory_access(filename="arch.memory_access.facts")
    program.arch_memory_access = read_csv::<(AccessMode, Address, OperandIndex, OperandIndex, Register, RegNullable, RegNullable, i64, i64)>(&get_path("arch.memory_access.facts"))
        .map(|(a, b, c, d, e, f, g, h, i)| (a, b, c, d, e, f, g, h, i))
        .collect_vec();

    // .input arch_move_reg_imm(filename="arch.move_reg_imm.facts")
    program.arch_move_reg_imm = read_csv::<(Address, Register, i64, OperandIndex)>(&get_path("arch.move_reg_imm.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    // .input arch_move_reg_reg(filename="arch.move_reg_reg.facts")
    program.arch_move_reg_reg = read_csv::<(Address, Register, Register)>(&get_path("arch.move_reg_reg.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();


    // arch_pc_relative_addr(0,"",0):- false.
    // Todo

    // .input arch_reg_arithmetic_operation(filename="arch.reg_arithmetic_operation.facts")
    program.arch_reg_arithmetic_operation = read_csv::<(Address, Register, Register, i64, i64)>(&get_path("arch.reg_arithmetic_operation.facts"))
        .map(|(a, b, c, d, e)| (a, b, c, d, e))
        .collect_vec();

    // .input arch_reg_reg_arithmetic_operation(filename="arch.reg_reg_arithmetic_operation.facts")
    program.arch_reg_reg_arithmetic_operation = read_csv::<(Address, Register, Register, Register, i64, i64)>(&get_path("arch.reg_reg_arithmetic_operation.facts"))
        .map(|(a, b, c, d, e, f)| (a, b, c, d, e, f))
        .collect_vec();

    // .input arch_register_size_bytes(filename="arch.register_size_bytes.facts")
    program.arch_register_size_bytes = read_csv::<(InputReg, u64)>(&get_path("arch.register_size_bytes.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    // .input arch_return_reg(filename="arch.return_reg.facts")
    program.arch_return_reg = read_csv::<(Register,)>(&get_path("arch.return_reg.facts"))
        .map(|(a,)| (a,))
        .collect_vec();


    // .input arch_stack_pointer(filename="arch.stack_pointer.facts")
    program.arch_stack_pointer = read_csv::<(Register,)>(&get_path("arch.stack_pointer.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    // .input arch_store_immediate(filename="arch.store_immediate.facts")
    program.arch_store_immediate = read_csv::<(Address, OperandIndex, OperandIndex, i64, RegNullable, RegNullable, i64, i64)>(&get_path("arch.store_immediate.facts"))
        .map(|(a, b, c, d, e, f, g, h)| (a, b, c, d, e, f, g, h))
        .collect_vec();

    // arch_store_immediate(0,0,0,0,"NONE","NONE",0,0):- false.
    // Todo

    // .input base_address
    program.base_address = read_csv::<(Address,)>(&get_path("base_address.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    // .input base_relative_operation
    program.base_relative_operation = read_csv::<(Address, Address)>(&get_path("base_relative_operation.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    // .input binary_format
    program.binary_format = read_csv::<(String,)>(&get_path("binary_format.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    // .input block
    program.block = read_csv::<(Address,)>(&get_path("block.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    // .input block_last_instruction
    // .input block_instruction_next
    // .input call_tls_get_addr
    // .input cmp_immediate_to_reg
    // .input cmp_reg_to_reg
    // .input code_in_block
    // .input conditional_jump
    // .input data_access
    // .input data_segment
    // .input defined_symbol
    // .input direct_call
    // .input direct_jump
    // .input got_reference_pointer
    // .input got_section
    // .input instruction
    // .input instruction_displacement_offset
    // .input instruction_get_dest_op
    // .input instruction_get_op
    // .input instruction_get_src_op
    // .input instruction_has_relocation
    // .input inter_procedural_edge
    // .input is_padding
    // .input is_xor_reset
    // .input limit_reg_op
    // .input limit_type_map
    // .input loaded_section
    // .input lsda_callsite_addresses
    // .input may_fallthrough
    // .input next
    // .input no_return_call_propagated

    program.block_last_instruction = read_csv::<(Address, Address)>(&get_path("block_last_instruction.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.block_instruction_next = read_csv::<(Address, Address, Address)>(&get_path("block_instruction_next.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.call_tls_get_addr = read_csv::<(Address, Register)>(&get_path("call_tls_get_addr.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.cmp_immediate_to_reg = read_csv::<(Address, Register, OperandIndex, i64)>(&get_path("cmp_immediate_to_reg.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.cmp_reg_to_reg = read_csv::<(Address, Register, Register)>(&get_path("cmp_reg_to_reg.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.code_in_block = read_csv::<(Address, Address)>(&get_path("code_in_block.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.conditional_jump = read_csv::<(Address,)>(&get_path("conditional_jump.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.data_access = read_csv::<(Address, OperandIndex, RegNullable, RegNullable, RegNullable, i64, i64, u64)>(&get_path("data_access.facts"))
        .map(|(a, b, c, d, e, f, g, h)| (a, b, c, d, e, f, g, h))
        .collect_vec();

    program.data_segment = read_csv::<(Address, Address)>(&get_path("data_segment.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.defined_symbol = read_csv::<(Address, u64, String, String, String, u64, String, u64, String)>(&get_path("defined_symbol.facts"))
        .map(|(a, b, c, d, e, f, g, h, i)| (a, b, c, d, e, f, g, h, i))
        .collect_vec();

    program.direct_call = read_csv::<(Address, Address)>(&get_path("direct_call.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.direct_jump = read_csv::<(Address, Address)>(&get_path("direct_jump.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.got_reference_pointer = read_csv::<(Address,)>(&get_path("got_reference_pointer.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.got_section = read_csv::<(String,)>(&get_path("got_section.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.instruction = read_csv::<(Address, u64, String, String, OperandCode, OperandCode, OperandCode, OperandCode, u64, u64)>(&get_path("instruction.facts"))
        .map(|(a, b, c, d, e, f, g, h, i, j)| (a, b, c, d, e, f, g, h, i, j))
        .collect_vec();

    program.instruction_displacement_offset = read_csv::<(Address, OperandIndex, u64, u64)>(&get_path("instruction_displacement_offset.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.instruction_get_dest_op = read_csv::<(Address, OperandIndex, OperandCode)>(&get_path("instruction_get_dest_op.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.instruction_get_op = read_csv::<(Address, OperandIndex, OperandCode)>(&get_path("instruction_get_op.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.instruction_get_src_op = read_csv::<(Address, OperandIndex, OperandCode)>(&get_path("instruction_get_src_op.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.instruction_has_relocation = read_csv::<(Address, Address)>(&get_path("instruction_has_relocation.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.inter_procedural_edge = read_csv::<(Address, Address)>(&get_path("inter_procedural_edge.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.is_padding = read_csv::<(Address,)>(&get_path("is_padding.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.is_xor_reset = read_csv::<(Address,)>(&get_path("is_xor_reset.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.limit_reg_op = read_csv::<(Address, Register, Register, i64)>(&get_path("limit_reg_op.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.limit_type_map = read_csv::<(ConditionCode, LimitType, LimitType, i64, i64)>(&get_path("limit_type_map.facts"))
        .map(|(a, b, c, d, e)| (a, b, c, d, e))
        .collect_vec();

    program.loaded_section = read_csv::<(Address, Address, String)>(&get_path("loaded_section.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.lsda_callsite_addresses = read_csv::<(Address, Address, Address)>(&get_path("lsda_callsite_addresses.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.may_fallthrough = read_csv::<(Address, Address)>(&get_path("may_fallthrough.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.next = read_csv::<(Address, Address)>(&get_path("next.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.no_return_call_propagated = read_csv::<(Address,)>(&get_path("no_return_call_propagated.facts"))
        .map(|(a,)| (a,))
        .collect_vec();


    // .input no_value_reg_limit
    // .input op_immediate
    // .input op_immediate_and_reg
    // .input op_indirect
    // .input op_indirect_mapped
    // .input op_regdirect
    // .input op_regdirect_contains_reg
    // .input pc_relative_operand
    // .input possible_rva_operand
    // .input reg_call
    // .input reg_def_use_block_last_def(filename="reg_def_use.block_last_def.facts")
    // .input reg_def_use_def(filename="reg_def_use.def.facts")
    // .input reg_def_use_defined_in_block(filename="reg_def_use.defined_in_block.facts")
    // .input reg_def_use_flow_def(filename="reg_def_use.flow_def.facts")
    // .input reg_def_use_live_var_def(filename="reg_def_use.live_var_def.facts")
    // .input reg_def_use_ref_in_block(filename="reg_def_use.ref_in_block.facts")
    
    program.no_value_reg_limit = read_csv::<(Address,)>(&get_path("no_value_reg_limit.facts"))
    .map(|(a,)| (a,))
    .collect_vec();

    program.op_immediate = read_csv::<(OperandCode, i64, u64)>(&get_path("op_immediate.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.op_immediate_and_reg = read_csv::<(Address, String, Register, OperandIndex, i64)>(&get_path("op_immediate_and_reg.facts"))
        .map(|(a, b, c, d, e)| (a, b, c, d, e))
        .collect_vec();

    program.op_indirect = read_csv::<(OperandCode, InputReg, InputReg, InputReg, i64, i64, u64)>(&get_path("op_indirect.facts"))
        .map(|(a, b, c, d, e, f, g)| (a, b, c, d, e, f, g))
        .collect_vec();

    program.op_indirect_mapped = read_csv::<(OperandCode, RegNullable, RegNullable, RegNullable, i64, i64, u64)>(&get_path("op_indirect_mapped.facts"))
        .map(|(a, b, c, d, e, f, g)| (a, b, c, d, e, f, g))
        .collect_vec();

    program.op_regdirect = read_csv::<(OperandCode, InputReg)>(&get_path("op_regdirect.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.op_regdirect_contains_reg = read_csv::<(OperandCode, Register)>(&get_path("op_regdirect_contains_reg.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.pc_relative_operand = read_csv::<(Address, OperandIndex, Address)>(&get_path("pc_relative_operand.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.possible_rva_operand = read_csv::<(Address, OperandIndex, Address)>(&get_path("possible_rva_operand.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.reg_call = read_csv::<(Address, Register)>(&get_path("reg_call.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.reg_def_use_block_last_def = read_csv::<(Address, Address, Register)>(&get_path("reg_def_use.block_last_def.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.reg_def_use_def = read_csv::<(Address, Register)>(&get_path("reg_def_use.def.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.reg_def_use_defined_in_block = read_csv::<(Address, Register)>(&get_path("reg_def_use.defined_in_block.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.reg_def_use_flow_def = read_csv::<(Address, Register, Address, i64)>(&get_path("reg_def_use.flow_def.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.reg_def_use_live_var_def = read_csv::<(Address, Register, Register, Address)>(&get_path("reg_def_use.live_var_def.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.reg_def_use_ref_in_block = read_csv::<(Address, Register)>(&get_path("reg_def_use.ref_in_block.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();


    // .input reg_def_use_return_block_end(filename="reg_def_use.return_block_end.facts")
    // .input reg_def_use_used(filename="reg_def_use.used.facts")
    // .input reg_def_use_used_in_block(filename="reg_def_use.used_in_block.facts")
    // .input reg_jump
    // .input reg_map
    // .input reg_used_for
    // .input register_access
    // .input relative_address
    // .input relative_address_start
    // .input relocation
    // .input relocation_adjustment_total
    // .input simple_data_access_pattern
    // .input stack_base_reg_move
    // .input stack_def_use_block_last_def(filename="stack_def_use.block_last_def.facts")
    // .input stack_def_use_def(filename="stack_def_use.def.facts")
    // .input stack_def_use_defined_in_block(filename="stack_def_use.defined_in_block.facts")
    // .input stack_def_use_live_var_def(filename="stack_def_use.live_var_def.facts")
    // .input stack_def_use_moves_limit(filename="stack_def_use.moves_limit.facts")
    // .input stack_def_use_ref_in_block(filename="stack_def_use.ref_in_block.facts")
    // .input stack_def_use_used(filename="stack_def_use.used.facts")
    // .input stack_def_use_used_in_block(filename="stack_def_use.used_in_block.facts")
    // .input step_limit
    // .input symbol
    // .input symbolic_expr_from_relocation
    // .input take_address
    // .input tls_descriptor
    // .input tls_index
    // .input tls_segment
    // .input track_register
    
    program.reg_def_use_return_block_end = read_csv::<(Address, Address, Address, Address)>(&get_path("reg_def_use.return_block_end.facts"))
    .map(|(a, b, c, d)| (a, b, c, d))
    .collect_vec();

    program.reg_def_use_used = read_csv::<(Address, Register, OperandIndex)>(&get_path("reg_def_use.used.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.reg_def_use_used_in_block = read_csv::<(Address, Address, Register, OperandIndex)>(&get_path("reg_def_use.used_in_block.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.reg_jump = read_csv::<(Address, Register)>(&get_path("reg_jump.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.reg_map = read_csv::<(InputReg, Register)>(&get_path("reg_map.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.reg_used_for = read_csv::<(Address, Register, String)>(&get_path("reg_used_for.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.register_access = read_csv::<(Address, InputReg, AccessMode)>(&get_path("register_access.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.relative_address = read_csv::<(Address, u64, Address, Address, Address, String)>(&get_path("relative_address.facts"))
        .map(|(a, b, c, d, e, f)| (a, b, c, d, e, f))
        .collect_vec();

    program.relative_address_start = read_csv::<(Address, u64, Address, Address, String)>(&get_path("relative_address_start.facts"))
        .map(|(a, b, c, d, e)| (a, b, c, d, e))
        .collect_vec();

    program.relocation = read_csv::<(Address, String, String, i64, u64, String, String)>(&get_path("relocation.facts"))
        .map(|(a, b, c, d, e, f, g)| (a, b, c, d, e, f, g))
        .collect_vec();

    program.relocation_adjustment_total = read_csv::<(Address, i64)>(&get_path("relocation_adjustment_total.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.simple_data_access_pattern = read_csv::<(Address, u64, u64, Address)>(&get_path("simple_data_access_pattern.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.stack_base_reg_move = read_csv::<(Address, Address, Register, Register)>(&get_path("stack_base_reg_move.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.stack_def_use_block_last_def = read_csv::<(Address, Address, StackVar)>(&get_path("stack_def_use.block_last_def.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.stack_def_use_def = read_csv::<(Address, StackVar)>(&get_path("stack_def_use.def.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.stack_def_use_defined_in_block = read_csv::<(Address, StackVar)>(&get_path("stack_def_use.defined_in_block.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.stack_def_use_live_var_def = read_csv::<(Address, StackVar, StackVar, Address)>(&get_path("stack_def_use.live_var_def.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.stack_def_use_moves_limit = read_csv::<(u64,)>(&get_path("stack_def_use.moves_limit.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.stack_def_use_ref_in_block = read_csv::<(Address, StackVar)>(&get_path("stack_def_use.ref_in_block.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.stack_def_use_used = read_csv::<(Address, StackVar, OperandIndex)>(&get_path("stack_def_use.used.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.stack_def_use_used_in_block = read_csv::<(Address, Address, StackVar, OperandIndex)>(&get_path("stack_def_use.used_in_block.facts"))
        .map(|(a, b, c, d)| (a, b, c, d))
        .collect_vec();

    program.step_limit = read_csv::<(u64,)>(&get_path("step_limit.facts"))
        .map(|(a,)| (a,))
        .collect_vec();

    program.symbol = read_csv::<(Address, u64, String, String, String, u64, String, u64, String)>(&get_path("symbol.facts"))
        .map(|(a, b, c, d, e, f, g, h, i)| (a, b, c, d, e, f, g, h, i))
        .collect_vec();

    program.symbolic_expr_from_relocation = read_csv::<(Address, u64, String, i64, Address)>(&get_path("symbolic_expr_from_relocation.facts"))
        .map(|(a, b, c, d, e)| (a, b, c, d, e))
        .collect_vec();

    program.take_address = read_csv::<(Address, Address)>(&get_path("take_address.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.tls_descriptor = read_csv::<(Address, u64)>(&get_path("tls_descriptor.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.tls_index = read_csv::<(Address, u64)>(&get_path("tls_index.facts"))
        .map(|(a, b)| (a, b))
        .collect_vec();

    program.tls_segment = read_csv::<(Address, Address, u64)>(&get_path("tls_segment.facts"))
        .map(|(a, b, c)| (a, b, c))
        .collect_vec();

    program.track_register = read_csv::<(Register,)>(&get_path("track_register.facts"))
        .map(|(a,)| (a,))
        .collect_vec();


}
