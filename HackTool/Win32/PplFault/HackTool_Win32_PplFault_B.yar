
rule HackTool_Win32_PplFault_B{
	meta:
		description = "HackTool:Win32/PplFault.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 66 52 65 67 69 73 74 65 72 53 79 6e 63 52 6f 6f 74 } //CfRegisterSyncRoot  1
		$a_80_1 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //MiniDumpWriteDump  1
		$a_80_2 = {5c 44 65 76 69 63 65 5c 50 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 } //\Device\PhysicalMemory  1
		$a_03_3 = {c7 03 d3 c0 ad 1b 90 02 10 c7 43 04 ef be ad de 90 00 } //10
		$a_03_4 = {48 87 c9 41 b8 3c 00 00 00 48 87 d2 4d 90 02 10 87 c0 4d 87 90 00 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=12
 
}