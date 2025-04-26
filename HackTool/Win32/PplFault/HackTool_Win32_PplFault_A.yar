
rule HackTool_Win32_PplFault_A{
	meta:
		description = "HackTool:Win32/PplFault.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 66 52 65 67 69 73 74 65 72 53 79 6e 63 52 6f 6f 74 } //CfRegisterSyncRoot  1
		$a_80_1 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //MiniDumpWriteDump  1
		$a_03_2 = {48 87 c9 c7 ?? ?? 48 87 d2 4d c7 ?? ?? 87 c0 4d 87 66 c7 ?? ?? c9 } //1
		$a_03_3 = {4c 8b e8 c7 44 24 ?? d3 c0 ad 1b c7 44 24 ?? ef be ad de } //10
		$a_01_4 = {c7 03 d3 c0 ad 1b c7 43 04 ef be ad de } //10
		$a_03_5 = {23 65 9c 11 ?? ?? ?? 7b 40 6b 44 ?? ?? ?? b0 e3 e0 30 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*10+(#a_01_4  & 1)*10+(#a_03_5  & 1)*10) >=12
 
}