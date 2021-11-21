#include <gtest/gtest.h>

#include <limits.h>

extern "C" {
#include "../vm_basic.h"
}

/* add instruction */

TEST(process_instruction_test, add_imm_to_reg64)
{
	int32_t imm = 1234;
	uint64_t org_value = 100;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .value = org_value,
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::RAX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.value, org_value + imm);
}

TEST(process_instruction_test, add_imm_to_reg32)
{
	int32_t imm = 1234;
	uint32_t org_value = 100;
	struct vm_ctx ctx {
		.registers = {
		    .rbp = {
			.ebp = {
			    .value = org_value,
			},
		    },
		},
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::EBP,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rbp.ebp.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rbp.ebp.value, org_value + imm);
}

TEST(process_instruction_test, add_imm_to_reg16)
{
	int16_t imm = 126;
	uint16_t org_value = 100;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .ax = {
					  .value = org_value,
				      },
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, org_value + imm);
}

TEST(process_instruction_test, add_imm_to_reg8)
{
	uint8_t imm = 123;
	uint8_t org_value = 5;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .ax = {
					  .al = org_value,
				      },
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AL,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.al, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, org_value + imm);
}

TEST(process_instruction_test, add_imm_to_reg8_set_cf)
{
	uint8_t imm = 10;
	uint8_t org_value = 250;
	uint8_t result = org_value + imm;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .ax = {
					  .al = org_value,
				      },
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AL,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.al, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, result);
	EXPECT_EQ(ctx.registers.rflags, 1 << CF | 1 << AF);
}

TEST(process_instruction_test, add_imm_to_reg16_set_cf)
{
	uint16_t imm = 100;
	uint16_t org_value = UINT16_MAX - 20;
	uint16_t result = org_value + imm;
	struct vm_ctx ctx {
		.registers = {
		    .rax = {
			.eax = {
			    .ax {
				.value = org_value,
			    },
			},
		    },
		},
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, result);
	EXPECT_EQ(ctx.registers.rflags, 1 << CF);
}

TEST(process_instruction_test, add_imm_to_reg32_set_cf)
{
	uint32_t imm = 100;
	uint32_t org_value = UINT32_MAX - 20;
	uint32_t result = org_value + imm;
	struct vm_ctx ctx {
		.registers = {
			.rax = {
			    .eax = {
				.value = org_value,
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::EAX,
			    },
			},
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.value, result);
	EXPECT_EQ(ctx.registers.rflags, 1 << CF);
}

TEST(process_instruction_test, add_imm_to_reg16_set_cf_pf_af_of)
{
	int16_t imm = -100;
	int16_t org_value = INT16_MIN + 10;
	int16_t result = org_value + imm;
	struct vm_ctx ctx {
		.registers = {
			.rax = {
			    .eax = {
				.ax = {
				    .value = (uint16_t)org_value,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.value, (uint16_t)org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, result);
	EXPECT_EQ(ctx.registers.rflags, 1 << CF | 1 << PF | 1 << AF | 1 << OF);
}

TEST(process_instruction_test, add_imm_to_reg32_set_sf_of)
{
	uint32_t imm = 100;
	uint32_t org_value = INT32_MAX - 20;
	uint32_t result = org_value + imm;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .value = org_value,
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::EAX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.value, result);
	EXPECT_EQ(ctx.registers.rflags, 1 << SF | 1 << OF);
}

TEST(process_instruction_test, add_imm_to_mem)
{
	int32_t imm = 1234;
	uint64_t org_value = 100;
	uint64_t dst = org_value;
	struct vm_ctx ctx {
		.registers = {.rax = {.value = (uint64_t)&dst},
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::ADD,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = RAX, .size = 64},
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.value, (uint64_t)&dst);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(dst, org_value + imm);
}

/* mov instruction */

TEST(process_instruction_test, mov_imm_to_reg64)
{
	int32_t imm = 1234;
	uint64_t org_value = 100;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .value = org_value,
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MOV,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::RAX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.value, imm);
}

TEST(process_instruction_test, mov_imm_to_reg32)
{
	int32_t imm = 1234;
	uint32_t org_value = 100;
	struct vm_ctx ctx {
		.registers = {.rbp = {
				  .ebp = {
				      .value = org_value,
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MOV,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::EBP,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rbp.ebp.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rbp.ebp.value, imm);
}

TEST(process_instruction_test, mov_imm_to_reg16)
{
	int16_t imm = 126;
	uint16_t org_value = 100;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .ax = {
					  .value = org_value,
				      },
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MOV,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AX,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.value, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, imm);
}

TEST(process_instruction_test, mov_imm_to_reg8)
{
	uint8_t imm = 123;
	uint8_t org_value = 5;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .ax = {
					  .al = org_value,
				      },
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MOV,
		.basic = {
			.src = {
			    .type = OPERAND::IMM,
			    .data = {
				.imm = imm,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = REG::AL,
			    },
			}
		}
	};

	EXPECT_EQ(ctx.registers.rax.eax.ax.al, org_value);
	EXPECT_EQ(process_instr(&instr, &ctx), 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, imm);
}

TEST(process_instruction_test, mov_mem64_to_mem64)
{
	uint64_t src_org = 12345;
	uint64_t dst_org = 332;
	uint64_t src = src_org;
	uint64_t dst = dst_org;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {.value = (uint64_t)&dst},
			.rax = {.value = (uint64_t)&src}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MOV,
		.basic = {
			.src = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = RAX, .size = 64},
			    },
			},
			.dst = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = RBX, .size = 64},
			    },
			}
		}
	};

	EXPECT_EQ(src, src_org);
	EXPECT_EQ(dst, dst_org);
	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(src, src_org);
	EXPECT_EQ(dst, src_org);
}

TEST(process_instruction_test, mov_mem32_to_mem32)
{
	uint32_t src_org = 12345;
	uint32_t dst_org = 332;
	uint32_t src = src_org;
	uint32_t dst = dst_org;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {.value = (uint64_t)&dst},
			.rax = {.value = (uint64_t)&src}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MOV,
		.basic = {
			.src = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = RAX, .size = 32},
			    },
			},
			.dst = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = RBX, .size = 32},
			    },
			}
		}
	};

	EXPECT_EQ(src, src_org);
	EXPECT_EQ(dst, dst_org);
	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(src, src_org);
	EXPECT_EQ(dst, src_org);
}

TEST(process_instruction_test, lea_mem_to_reg64)
{
	uint64_t rax = 128;
	uint64_t rbx = 0xdead;
	uint8_t scale = 4;
	int64_t disp = 0xc0de;
	struct vm_ctx ctx {
		.registers = {.rbx = {
				  .value = rbx,
			      },
			.rax = {
			    .value = rax,
			},
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::LEA,
		.basic = {
			.src = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = RAX,
				    .index = RBX,
				    .scale = scale,
				    .disp = disp,
				    .size = 64},
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RAX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.value, rax + rbx * scale + disp);
}

TEST(process_instruction_test, lea_mem_to_reg32)
{
	uint32_t eax = 128;
	uint32_t ebx = 0xdead;
	uint8_t scale = 4;
	int32_t disp = 0xc0de;
	struct vm_ctx ctx {
		.registers = {.rbx = {
				  .ebx = {
				      .value = ebx,
				  },
			      },
			.rax = {
			    .eax = {
				.value = eax,
			    },
			},
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::LEA,
		.basic = {
			.src = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = EAX,
				    .index = EBX,
				    .scale = scale,
				    .disp = disp,
				    .size = 64},
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.value, eax + ebx * scale + disp);
}

TEST(process_instruction_test, lea_mem_to_reg16)
{
	uint16_t ax = 128;
	uint16_t bx = 256;
	uint8_t scale = 4;
	int16_t disp = 512;
	struct vm_ctx ctx {
		.registers = {.rbx = {
				  .ebx = {
				      .bx = {
					  .value = bx,
				      },
				  },
			      },
			.rax = {
			    .eax = {
				.ax = {
				    .value = ax,
				},
			    },
			},
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::LEA,
		.basic = {
			.src = {
			    .type = OPERAND::MEM,
			    .data = {
				.mem = {.base = AX,
				    .index = BX,
				    .scale = scale,
				    .disp = disp,
				    .size = 64},
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, ax + bx * scale + disp);
}

TEST(process_instruction_test, sext_cwde)
{
	int16_t v = -250;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {
				      .ax = {.value = (uint16_t)v},
				  },
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::SEXT,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			}
		}
	};

	EXPECT_EQ((int16_t)ctx.registers.rax.eax.ax.value, v);
	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ((int32_t)ctx.registers.rax.eax.value, v);
}

TEST(process_instruction_test, sext_cdq)
{
	int32_t v = -12345;
	struct vm_ctx ctx {
		.registers = {.rax = {
				  .eax = {.value = (uint32_t)v},
			      },
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::SEXT,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			}
		}
	};

	EXPECT_EQ((int32_t)ctx.registers.rax.eax.value, v);
	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ((int32_t)ctx.registers.rax.eax.value, v);
	EXPECT_EQ((int32_t)ctx.registers.rdx.edx.value, -1);
}

TEST(process_instruction_test, imul_r8)
{
	int8_t a = 5;
	int8_t b = 5;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {.bl = (uint8_t)b},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .al = (uint8_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::IMUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BL,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AL,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, a * b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.bl, b);
	EXPECT_EQ(ctx.registers.rax.eax.ax.ah, 0);
}

TEST(process_instruction_test, mul_r8)
{
	uint8_t a = 5;
	uint8_t b = 5;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {.bl = (uint8_t)b},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .al = (uint8_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BL,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AL,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, a * b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.bl, b);
	EXPECT_EQ(ctx.registers.rax.eax.ax.ah, 0);
}

TEST(process_instruction_test, mul_r8_of)
{
	uint8_t a = 100;
	uint8_t b = 5;
	uint16_t result = a * b;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {.bl = (uint8_t)b},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .al = (uint8_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BL,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AL,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, result);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.bl, b);
}

TEST(process_instruction_test, mul_r16)
{
	uint16_t a = 50;
	uint16_t b = 40;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {.value = (uint16_t)b},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .value = (uint16_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = DX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, a * b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.dx.value, 0);
}

TEST(process_instruction_test, mul_r16_of)
{
	uint16_t a = INT16_MAX / 4;
	uint16_t b = 16;
	uint32_t result = a * b;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {.value = (uint16_t)b},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .value = (uint16_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = DX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, (uint16_t)(a * b));
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.dx.value, (result >> 16) & 0xffff);
}

TEST(process_instruction_test, mul_r32)
{
	uint32_t a = 12345;
	uint32_t b = 125;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.value = (uint32_t)b,
			    },
			},
			.rax = {
			    .eax = {
				.value = (uint32_t)a,
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EBX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EDX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.value, a * b);
	EXPECT_EQ(ctx.registers.rbx.ebx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.value, 0);
}

TEST(process_instruction_test, mul_r32_of)
{
	uint32_t a = INT_MAX / 4;
	uint32_t b = 32;
	uint64_t result = (int64_t)a * b;

	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.value = (uint32_t)b,
			    },
			},
			.rax = {
			    .eax = {
				.value = (uint32_t)a,
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::MUL,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EBX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EDX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ((int32_t)ctx.registers.rax.eax.value, (uint32_t)(a * b));
	EXPECT_EQ(ctx.registers.rbx.ebx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.value, (uint32_t)(result >> 32));
}

TEST(process_instruction_test, div_r8)
{
	uint8_t a = 250;
	uint8_t b = 20;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {.bl = b},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .al = a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::DIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BL,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			},
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, a / b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.bl, b);
	EXPECT_EQ(ctx.registers.rax.eax.ax.ah, a % b);
}

TEST(process_instruction_test, div_r16)
{
	uint16_t a = 1024;
	uint16_t b = 20;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {
				    .value = b,
				},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .value = a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::DIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = DX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, a / b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.dx.value, a % b);
}

TEST(process_instruction_test, div_r32)
{
	uint32_t a = UINT_MAX / 2;
	uint32_t b = 123456;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.value = b,
			    },
			},
			.rax = {
			    .eax = {
				.value = a,
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::DIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EBX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EDX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.value, a / b);
	EXPECT_EQ(ctx.registers.rbx.ebx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.value, a % b);
}

TEST(process_instruction_test, div_r64)
{
	uint64_t a = UINT64_MAX / 2;
	uint64_t b = 123456;
	struct vm_ctx ctx {
		.registers = {.rbx = {
				  .value = b,
			      },
			.rax = {
			    .value = a,
			},
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::DIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RBX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RAX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RDX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.value, a / b);
	EXPECT_EQ(ctx.registers.rbx.value, b);
	EXPECT_EQ(ctx.registers.rdx.value, a % b);
}

TEST(process_instruction_test, idiv_r8)
{
	int8_t a = 111;
	int8_t b = 20;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {
				    .bl = (uint8_t)b,
				},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .al = (uint8_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::IDIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = BL,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = AX,
			    },
			},
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.al, a / b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.bl, b);
	EXPECT_EQ(ctx.registers.rax.eax.ax.ah, a % b);
}

TEST(process_instruction_test, idiv_r16)
{
	int16_t a = 1024;
	int16_t b = 20;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.bx = {
				    .value = (uint16_t)b,
				},
			    },
			},
			.rax = {
			    .eax = {
				.ax = {
				    .value = (uint16_t)a,
				},
			    },
			}
		}
	};

	struct instruction_entry instr = {
	    .opcode = OPCODE::IDIV,
	    .basic = {
		.src = {
		    .type = OPERAND::REG,
		    .data = {
			.reg = BX,
		    },
		},
		.dst = {
		    .type = OPERAND::REG,
		    .data = {
			.reg = AX,
		    },
		},
		.opt0 = {
		    .type = OPERAND::REG,
		    .data = {
			.reg = DX,
		    },
		},
	    },
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.ax.value, a / b);
	EXPECT_EQ(ctx.registers.rbx.ebx.bx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.dx.value, a % b);
}

TEST(process_instruction_test, idiv_r32)
{
	int32_t a = INT_MAX / 2;
	int32_t b = 123456;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .ebx = {
				.value = (uint32_t)b,
			    },
			},
			.rax = {
			    .eax = {
				.value = (uint32_t)a,
			    },
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::IDIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EBX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EAX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = EDX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.eax.value, a / b);
	EXPECT_EQ(ctx.registers.rbx.ebx.value, b);
	EXPECT_EQ(ctx.registers.rdx.edx.value, a % b);
}

TEST(process_instruction_test, idiv_r64)
{
	int64_t a = INT64_MAX / 2;
	int64_t b = 123456;
	struct vm_ctx ctx {
		.registers = {
			.rbx = {
			    .value = (uint64_t)b,
			},
			.rax = {
			    .value = (uint64_t)a,
			}
		}
	};

	struct instruction_entry instr {
		.opcode = OPCODE::IDIV,
		.basic = {
			.src = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RBX,
			    },
			},
			.dst = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RAX,
			    },
			},
			.opt0 = {
			    .type = OPERAND::REG,
			    .data = {
				.reg = RDX,
			    },
			}
		}
	};

	int ret = process_instr(&instr, &ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(ctx.registers.rax.value, a / b);
	EXPECT_EQ(ctx.registers.rbx.value, b);
	EXPECT_EQ(ctx.registers.rdx.value, a % b);
}

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
