
rule VirTool_Win32_Obfuscator_ARK{
	meta:
		description = "VirTool:Win32/Obfuscator.ARK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 e1 ff 00 00 00 0f b6 55 90 01 01 33 ca 8b 45 90 01 01 89 45 90 01 01 88 08 89 45 90 01 01 8b 55 90 01 01 81 c2 90 01 04 39 55 90 01 01 0f 82 90 00 } //1
		$a_03_1 = {2b 4d f8 81 c1 90 01 04 88 0d 90 01 04 0f b6 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}