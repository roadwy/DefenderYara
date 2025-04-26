
rule VirTool_Win32_Obfuscator_OH{
	meta:
		description = "VirTool:Win32/Obfuscator.OH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 58 3c 8b 54 03 50 55 56 57 } //1
		$a_01_1 = {8b 00 39 48 18 75 f9 8b 15 } //1
		$a_01_2 = {2b 7d 34 83 3c 08 00 8d 14 08 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}