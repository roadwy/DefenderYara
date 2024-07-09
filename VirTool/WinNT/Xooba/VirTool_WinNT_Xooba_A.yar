
rule VirTool_WinNT_Xooba_A{
	meta:
		description = "VirTool:WinNT/Xooba.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 01 6a 07 6a 00 6a 00 8d ?? ?? ?? 50 8d ?? ?? ?? 50 68 81 00 00 00 8d ?? ?? ?? 50 } //1
		$a_02_1 = {03 c0 01 43 0c 8b 43 0c 33 d2 f7 35 ?? ?? ?? 00 8b c2 85 c0 76 0b } //1
		$a_00_2 = {4e 00 54 00 46 00 53 00 } //1 NTFS
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}