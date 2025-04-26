
rule VirTool_Win32_CobaltStrike_G{
	meta:
		description = "VirTool:Win32/CobaltStrike.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 57 6a 00 ff 75 08 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8d 45 fc 50 57 ff 75 f8 56 ff 75 08 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}