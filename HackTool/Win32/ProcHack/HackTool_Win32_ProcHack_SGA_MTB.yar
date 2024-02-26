
rule HackTool_Win32_ProcHack_SGA_MTB{
	meta:
		description = "HackTool:Win32/ProcHack.SGA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 73 75 70 65 72 2d 65 63 2e 63 6e } //02 00  www.super-ec.cn
		$a_01_1 = {5c 73 75 70 65 72 65 63 2e 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 2e 73 79 73 } //01 00  \superec.ProcessMemory.sys
		$a_01_2 = {5c 72 77 6d 2e 70 64 62 } //01 00  \rwm.pdb
		$a_01_3 = {69 61 6c 64 6e 77 78 66 } //00 00  ialdnwxf
	condition:
		any of ($a_*)
 
}