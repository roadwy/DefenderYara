
rule VirTool_Win32_CobaltStrike_F_entry{
	meta:
		description = "VirTool:Win32/CobaltStrike.F!entry,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0 } //1
		$a_03_1 = {4d 5a 52 45 e8 00 00 00 00 5b 89 df 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}