
rule VirTool_Win32_Samdumpz_A_dll{
	meta:
		description = "VirTool:Win32/Samdumpz.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 6a 05 ff 74 24 40 ff 15 ?? ?? ?? ?? 33 c9 } //1
		$a_03_1 = {50 68 ff ff 00 00 8d 44 ?? ?? 50 6a 00 8d 44 ?? ?? 50 ff 74 24 44 ff 54 24 28 89 44 24 64 } //1
		$a_03_2 = {50 6a 00 68 00 00 10 00 ff ?? 8b f8 } //1
		$a_03_3 = {50 6a 12 ff 74 24 2c ff 54 ?? ?? 85 c0 0f 88 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}