
rule VirTool_Win32_Samdumpz_B_dll{
	meta:
		description = "VirTool:Win32/Samdumpz.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 68 ff 0f 0f 00 8d 44 ?? ?? 89 5c 24 78 50 6a 00 89 9c 24 84 00 00 00 89 9c 24 88 00 00 00 89 9c 24 8c 00 00 00 c7 44 24 78 18 00 00 00 ff } //1
		$a_03_1 = {6a 01 68 00 00 00 02 8d 44 ?? ?? 50 6a 00 ff 54 ?? ?? 85 c0 0f 88 } //1
		$a_03_2 = {50 68 ff ff 00 00 8d 44 ?? ?? 50 6a 00 8d 44 ?? ?? 50 ff 74 24 40 ff 54 ?? ?? 89 44 24 54 } //1
		$a_03_3 = {50 6a 00 68 00 00 10 00 ff ?? 8b f0 89 74 24 5c 85 f6 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}