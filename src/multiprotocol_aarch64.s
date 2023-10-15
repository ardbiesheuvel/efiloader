// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

	.section ".text", "ax", %progbits
	.macro	wrap, ident:req
	.globl	\ident\()_wrapper
\ident\()_wrapper:
	stp	x29, x30, [sp, #-80]!
	mov	x29, sp
	stp	x1, x2, [sp, #24]
	stp	x3, x4, [sp, #40]
	stp	x5, x6, [sp, #56]
	str	x7, [sp, #72]
	add	x1, sp, #24
	bl	\ident
	ldp	x29, x30, [sp], #80
	ret
	.endmacro

	wrap	install_multiple_protocol_interfaces
	wrap	uninstall_multiple_protocol_interfaces
