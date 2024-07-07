
rule VirTool_Win32_Obfuscator_OP{
	meta:
		description = "VirTool:Win32/Obfuscator.OP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 00 c6 05 90 01 05 c6 05 90 01 05 c6 05 90 00 } //1
		$a_01_1 = {eb 00 0f b6 d1 81 f2 } //1
		$a_03_2 = {eb 00 8b 15 90 01 04 33 55 08 89 55 0c 0f b6 45 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_OP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.OP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 74 0a 8a 06 34 90 01 01 88 06 46 49 eb f1 59 49 eb 90 00 } //1
		$a_03_1 = {b9 ff 5f 00 00 83 f9 00 74 90 01 01 51 8b 85 90 01 03 00 8d b5 90 01 03 00 8b 8d 90 01 03 00 83 f9 00 90 00 } //1
		$a_02_2 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 47 6c 6f 62 61 6c 90 01 01 6c 6c 6f 63 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}