
rule VirTool_Win32_Parlsz_B_MTB{
	meta:
		description = "VirTool:Win32/Parlsz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 6a 00 ff 74 24 78 c7 84 24 c8 02 00 00 01 00 00 00 89 8c 24 d0 02 00 00 c7 84 24 d4 02 00 00 02 00 00 00 ff } //1
		$a_02_1 = {c7 44 24 60 00 00 00 00 8d ?? ?? ?? 50 6a 00 6a 00 56 8b 35 ?? ?? ?? ?? ff } //1
		$a_00_2 = {ff 74 24 1c 89 7c 24 6c 57 56 ff 74 24 24 ff } //1
		$a_02_3 = {6a 08 8d 84 ?? ?? ?? ?? ?? 50 6a 00 57 ff 74 24 58 ff b4 24 8c 00 00 00 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}