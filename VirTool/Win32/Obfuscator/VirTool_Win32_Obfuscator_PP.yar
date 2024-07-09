
rule VirTool_Win32_Obfuscator_PP{
	meta:
		description = "VirTool:Win32/Obfuscator.PP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b f1 c1 ee 05 03 74 24 0c 8b d9 c1 e3 04 03 5c 24 10 33 f3 8d 1c 0a 33 f3 2b c6 8b f0 c1 ee 05 03 74 24 14 8b d8 c1 e3 04 03 5c 24 18 33 f3 8d 1c 02 33 f3 2b ce } //1
		$a_02_1 = {8d 7e 01 57 56 8d 4e ff 51 8d 56 fe 52 8d 4e fd 51 8d 56 fc 52 8d 4e fb 51 83 c6 fa 56 ff d0 3c 05 74 ?? 8d 54 24 14 52 8b f7 ff d3 68 ?? ?? ?? ?? 50 ff d5 eb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}