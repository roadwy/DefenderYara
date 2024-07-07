
rule VirTool_Win32_Obfuscator_OK{
	meta:
		description = "VirTool:Win32/Obfuscator.OK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 07 8b 4d 90 01 01 c1 e9 19 0b c1 89 45 90 01 01 8b 55 90 01 01 0f 90 01 01 02 33 45 90 01 01 89 45 90 00 } //1
		$a_03_1 = {0f b7 0c 4a 81 e1 ff 0f 00 00 8b 55 90 01 01 03 0a 8b 55 08 89 04 0a 90 00 } //1
		$a_03_2 = {eb 0f 58 2b 05 90 01 03 00 03 05 90 01 03 00 ff e0 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}