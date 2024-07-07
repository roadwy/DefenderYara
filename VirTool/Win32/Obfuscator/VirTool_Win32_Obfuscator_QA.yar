
rule VirTool_Win32_Obfuscator_QA{
	meta:
		description = "VirTool:Win32/Obfuscator.QA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 8b 55 90 01 01 3b 55 10 73 1e 8b 45 0c 03 45 90 01 01 0f b6 08 8b 55 08 03 55 90 01 01 0f b6 02 33 c1 8b 4d 08 03 4d 90 01 01 88 01 eb d1 8b e5 5d c2 0c 00 90 00 } //1
		$a_03_1 = {6a 00 6a 01 8b 15 90 01 04 52 ff 95 90 01 01 fe ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}