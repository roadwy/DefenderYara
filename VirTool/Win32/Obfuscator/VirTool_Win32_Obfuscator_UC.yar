
rule VirTool_Win32_Obfuscator_UC{
	meta:
		description = "VirTool:Win32/Obfuscator.UC,SIGNATURE_TYPE_PEHSTR_EXT,09 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 01 66 c7 00 e8 00 ff 36 e8 90 01 04 6a 02 66 c7 00 22 00 ff 36 e8 90 01 04 6a 03 66 89 18 ff 36 e8 90 01 04 6a 04 66 89 18 ff 36 e8 90 01 04 6a 05 66 89 18 ff 36 e8 90 01 04 6a 06 66 c7 00 68 00 ff 36 e8 90 00 } //01 00 
		$a_02_1 = {68 88 00 00 00 66 c7 00 01 00 ff 36 e8 90 01 04 68 89 00 00 00 66 c7 00 c7 00 ff 36 e8 90 01 04 68 8c 00 00 00 66 c7 00 eb 00 ff 36 e8 90 01 04 68 8d 00 00 00 66 c7 00 7c 00 ff 36 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}