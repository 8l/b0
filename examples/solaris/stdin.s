
	.section	.text,"ax"
	.align	4

	.globl	main
	.type	main,@function
	.align	16
main:
.L_y1:
	pushq	%rbp
.L_y2:
	movq	%rsp,%rbp
.L_y3:
	subq	$32,%rsp
	movl	%edi, -4(%rbp)
	movq	%rsi, -16(%rbp)
.L13:

/ File stdin.c:
/ Line 10
	movq	__stderr, %r8
	movq	__stdin, %rcx
	movq	__stdout, %rdx
	movq	$.L15+0, %rsi
	movq	__stdout, %rdi
	movl	$0, %eax
	call	fprintf
/ Line 11
	movl	$8, -32(%rbp)
	movl	$0, -28(%rbp)
	movq	-32(%rbp), %r8
	movq	%r8, %rdx
	movq	$.L16+0, %rsi
	movq	__stdout, %rdi
	movl	$0, %eax
	call	fprintf
/ Line 12
	movq	__stdin, %r8
	subq	__stdout, %r8
	movq	%r8, %rdx
	movq	$.L17+0, %rsi
	movq	__stdout, %rdi
	movl	$0, %eax
	call	fprintf
/ Line 13
	movl	$1, %edi
	movl	$0, %eax
	call	exit
/ Line 14
	movl	$0, -20(%rbp)
	jmp	.L12
	.align	4
.L12:
	movl	-20(%rbp), %eax
	leave
	ret
.L_y0:
	.size	main,.-main

	.section	.bss,"aw"
Bbss.bss:
	.type	Bbss.bss,@object
	.size	Bbss.bss,0

	.section	.data,"aw"
Ddata.data:
	.type	Ddata.data,@object
	.size	Ddata.data,0

	.section	.rodata,"a"
Drodata.rodata:
	.type	Drodata.rodata,@object
	.size	Drodata.rodata,0

	.section	.data,"aw"
	.globl	__stdout
	.align	8
__stdout:
	.quad	__iob+128
	.type	__stdout,@object
	.size	__stdout,8

	.section	.rodata1,"a"
	.align	8
.L15:
	.byte	0x53,0x74,0x64,0x6f,0x75,0x74,0x20,0x3d,0x20,0x25
	.byte	0x6c,0x78,0x2c,0x20,0x73,0x74,0x64,0x69,0x6e,0x20
	.byte	0x3d,0x20,0x25,0x6c,0x78,0x2c,0x20,0x73,0x74,0x64
	.byte	0x65,0x72,0x72,0x20,0x3d,0x20,0x25,0x6c,0x78,0xa
	.byte	0x0
	.set	.,.+7
	.type	.L15,@object
	.size	.L15,48

	.section	.data,"aw"
	.globl	__stdin
	.align	8
__stdin:
	.quad	__iob
	.type	__stdin,@object
	.size	__stdin,8
	.globl	__stderr
	.align	8
__stderr:
	.quad	__iob+256
	.type	__stderr,@object
	.size	__stderr,8

	.section	.rodata1,"a"
	.align	8
.L16:
	.byte	0x53,0x69,0x7a,0x65,0x6f,0x66,0x28,0x73,0x74,0x64
	.byte	0x69,0x6e,0x29,0x20,0x3d,0x20,0x25,0x6c,0x78,0xa
	.byte	0x0
	.set	.,.+3
	.type	.L16,@object
	.size	.L16,24
	.align	8
.L17:
	.byte	0x53,0x69,0x7a,0x65,0x4f,0x66,0x28,0x5f,0x4e,0x46
	.byte	0x69,0x6c,0x65,0x29,0x20,0x3d,0x20,0x25,0x6c,0x78
	.byte	0xa,0x0
	.type	.L17,@object
	.size	.L17,22
	.type	fprintf,@function
	.type	exit,@function

	.section	.eh_frame,"aL",link=.text,@unwind
	.align 8
.Lframe1:
	.long	.LECIE1-.LBCIE1
.LBCIE1:
	.long	0x0
	.byte	0x1
	.string	""
	.uleb128	0x1
	.sleb128	-8
	.byte	0x10
	.byte	0xc
	.uleb128	0x7
	.uleb128	0x8
	.byte	0x90
	.uleb128	0x1
	.byte	0x8
	.byte	0x3
	.byte	0x8
	.byte	0x6
	.byte	0x8
	.byte	0xc
	.byte	0x8
	.byte	0xd
	.byte	0x8
	.byte	0xe
	.byte	0x8
	.byte	0xf
	.align 8
.LECIE1:
	.long	.LEFDE1-.LBFDE1
.LBFDE1:
	.long	.LBFDE1-.Lframe1
	.quad	.L_y1
	.quad	.L_y0-.L_y1
	.cfa_advance_loc	.L_y2-.L_y1
	.byte	0xe
	.uleb128	0x10
	.byte	0x86
	.uleb128	0x2
	.cfa_advance_loc	.L_y3-.L_y2
	.byte	0xd
	.uleb128	0x6
	.align	8
.LEFDE1:

	.file	"stdin.c"
	.ident	"@(#)stdio.h	1.86	05/06/08 SMI"
	.ident	"@(#)feature_tests.h	1.26	06/09/19 SMI"
	.ident	"@(#)ccompile.h	1.3	05/06/08 SMI"
	.ident	"@(#)isa_defs.h	1.32	07/01/10 SMI"
	.ident	"@(#)stdio_iso.h	1.10	05/06/13 SMI"
	.ident	"@(#)va_list.h	1.17	05/06/08 SMI"
	.ident	"@(#)stdio_tag.h	1.5	05/06/08 SMI"
	.ident	"@(#)stdio_impl.h	1.16	06/04/18 SMI"
	.ident	"@(#)stdio_c99.h	1.3	05/06/08 SMI"
	.ident	"@(#)stdlib.h	1.56	07/05/23 SMI"
	.ident	"@(#)stdlib_iso.h	1.13	05/08/18 SMI"
	.ident	"@(#)stdlib_c99.h	1.3	05/06/08 SMI"
	.ident	"acomp: Sun C 5.9 SunOS_i386 Build47_dlight 2007/05/22"

	.globl	__fsr_init_value
__fsr_init_value = 0x0
/  Begin sdCreateSection : .debug_loc
/  Section Info: link_name/strtab=, entsize=0x1, adralign=0x1, flags=0x0
/  Section Data Blocks:
	.section .debug_loc
/  End sdCreateSection
/  Begin sdCreateSection : .debug_info
/  Section Info: link_name/strtab=, entsize=0x1, adralign=0x1, flags=0x0
/  Section Data Blocks:
/   reloc[0]: knd=2, off=14, siz=8, lab1=.debug_abbrev, lab2=, loff=0
/   reloc[1]: knd=2, off=208, siz=8, lab1=.debug_line, lab2=, loff=0
	.section .debug_info
	.byte 0xff,0xff,0xff,0xff,0xd0,0x00,0x00,0x00
	.byte 0x00,0x00,0x00,0x00,0x02,0x00
	.8byte .debug_abbrev
	.byte 0x08,0x01
	.ascii "stdin.c\0"
	.byte 0x0c
	.ascii "/export/home/darran/Projects/b0/examples/Solaris\0"
	.ascii " /opt/SUNWspro/prod/bin/cc -m64 -S  stdin.c\0"
	.ascii "Xa;R=Sun C 5.9 SunOS_i386 Build47_dlight 2007/05/22;backend;raw;cd;\0"
	.ascii "DBG_GEN 5.2.1\0"
	.8byte .debug_line
	.byte 0x00,0x00,0x00,0x00
/  End sdCreateSection
/  Begin sdCreateSection : .debug_line
/  Section Info: link_name/strtab=, entsize=0x1, adralign=0x1, flags=0x0
/  Section Data Blocks:
	.section .debug_line
	.byte 0xff,0xff,0xff,0xff,0x56,0x00,0x00,0x00
	.byte 0x00,0x00,0x00,0x00,0x02,0x00,0x4c,0x00
	.byte 0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00
	.byte 0xff,0x04,0x0a,0x00,0x01,0x01,0x01,0x01
	.byte 0x00,0x00,0x00,0x01,0x2f,0x65,0x78,0x70
	.byte 0x6f,0x72,0x74,0x2f,0x68,0x6f,0x6d,0x65
	.byte 0x2f,0x64,0x61,0x72,0x72,0x61,0x6e,0x2f
	.byte 0x50,0x72,0x6f,0x6a,0x65,0x63,0x74,0x73
	.byte 0x2f,0x62,0x30,0x2f,0x65,0x78,0x61,0x6d
	.byte 0x70,0x6c,0x65,0x73,0x2f,0x53,0x6f,0x6c
	.byte 0x61,0x72,0x69,0x73,0x00,0x00,0x73,0x74
	.byte 0x64,0x69,0x6e,0x2e,0x63,0x00,0x01,0x00
	.byte 0x00,0x00
/  End sdCreateSection
/  Begin sdCreateSection : .debug_abbrev
/  Section Info: link_name/strtab=, entsize=0x1, adralign=0x1, flags=0x0
/  Section Data Blocks:
	.section .debug_abbrev
	.byte 0x01,0x11,0x00,0x03,0x08,0x13,0x0b,0x1b
	.byte 0x08,0x85,0x44,0x08,0x87,0x44,0x08,0x25
	.byte 0x08,0x10,0x07,0x00,0x00,0x00
/  End sdCreateSection
