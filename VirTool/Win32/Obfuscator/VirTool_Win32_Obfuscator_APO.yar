
rule VirTool_Win32_Obfuscator_APO{
	meta:
		description = "VirTool:Win32/Obfuscator.APO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f be 45 08 0f be 4d 0c 33 c1 8b e5 5d c3 } //1
		$a_01_1 = {8a 02 88 45 fb 8b 4d 08 03 4d } //1
		$a_01_2 = {8b 45 10 8b 65 08 8b 6d 0c ff e0 8b e5 5d c2 0c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}