
rule VirTool_Win32_Obfuscator_AMD{
	meta:
		description = "VirTool:Win32/Obfuscator.AMD,SIGNATURE_TYPE_PEHSTR_EXT,32 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 c7 45 d8 3e 00 66 c7 45 da 4c 00 66 c7 45 dc 1d 00 c7 45 e4 03 00 00 00 } //1
		$a_01_1 = {8b 55 08 25 ff ff 00 00 8a 44 45 d8 8a 1c 11 32 d8 88 1c 11 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}