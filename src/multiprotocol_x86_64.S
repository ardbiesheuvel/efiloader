// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

	.section ".text", "ax", %progbits
	.macro	wrap, ident:req
	.globl	\ident\()_wrapper
\ident\()_wrapper:
	// Store the varargs in the shadow space on the stack
	mov	[rsp + 0x10], rdx
	mov	[rsp + 0x18], r8
	mov	[rsp + 0x20], r9

	// Pass the address of the varargs array as param #2
	lea	rdx, [rsp + 0x10]

	// Allocate new shadow space and realign the stack
	sub	rsp, 0x28

	// Call the Rust implementation
	call	\ident

	add	rsp, 0x28
	ret
	.endmacro

	wrap	install_multiple_protocol_interfaces
	wrap	uninstall_multiple_protocol_interfaces
