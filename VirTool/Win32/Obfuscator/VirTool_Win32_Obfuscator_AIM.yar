
rule VirTool_Win32_Obfuscator_AIM{
	meta:
		description = "VirTool:Win32/Obfuscator.AIM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {05 0a a8 04 00 89 85 7c ff ff ff c7 45 8c 00 00 00 00 c7 45 c4 00 00 00 00 81 7d dc 03 0d 00 00 7f 2f } //1
		$a_00_1 = {00 00 76 00 6b 00 6c 00 64 00 65 00 00 00 } //1
		$a_00_2 = {0d 6f 79 47 65 74 44 65 76 43 61 70 73 57 00 00 57 00 69 00 6e 00 6d 00 6d 00 2e 00 64 00 6c 00 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}