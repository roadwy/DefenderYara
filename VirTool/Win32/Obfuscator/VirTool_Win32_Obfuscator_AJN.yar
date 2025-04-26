
rule VirTool_Win32_Obfuscator_AJN{
	meta:
		description = "VirTool:Win32/Obfuscator.AJN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {74 24 28 fc bf 90 09 07 00 9c 60 68 90 01 0e 03 34 24 90 03 1e 1f 90 03 0f 0b 8a 0e 0f b6 c1 8d 76 01 ff 34 85 90 01 04 c3 ac 0f b6 c0 ff 34 85 90 01 04 c3 90 03 0d 0e 8a 06 0f b6 c0 46 ff 34 85 90 01 04 c3 8a 06 46 0f b6 c0 8d 14 85 90 01 04 ff 22 90 00 01 } //1
		$a_68_1 = {2f 76 e0 e8 90 01 04 68 5e ce d6 e9 89 45 e4 e8 90 01 04 } //11008
	condition:
		((#a_13_0  & 1)*1+(#a_68_1  & 1)*11008) >=2
 
}