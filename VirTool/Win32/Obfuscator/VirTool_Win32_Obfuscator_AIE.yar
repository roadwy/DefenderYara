
rule VirTool_Win32_Obfuscator_AIE{
	meta:
		description = "VirTool:Win32/Obfuscator.AIE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 95 d8 f6 ff ff ff d2 33 c0 5f 5e 8b 4d dc } //1
		$a_01_1 = {55 8b ec b8 1e 0c 00 00 5d c3 } //1
		$a_01_2 = {8a 55 ff 88 95 ab f3 ff ff 8b 45 f0 8a 8d ab f3 ff ff 88 8c 05 b8 f3 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}