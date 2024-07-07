
rule VirTool_Win64_Obfuscator_ADB{
	meta:
		description = "VirTool:Win64/Obfuscator.ADB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 41 28 ca 23 c1 00 } //1
		$a_01_1 = {b9 9e f9 96 ca e8 } //1
		$a_01_2 = {b9 b9 06 a0 bf e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}