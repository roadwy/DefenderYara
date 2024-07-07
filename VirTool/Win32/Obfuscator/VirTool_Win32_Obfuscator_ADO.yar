
rule VirTool_Win32_Obfuscator_ADO{
	meta:
		description = "VirTool:Win32/Obfuscator.ADO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 27 47 c0 ec 04 2a c4 73 f6 8a 47 ff 24 0f 3c 90 01 01 75 03 5a f7 d2 42 3c 00 74 42 3c 01 90 00 } //1
		$a_03_1 = {8b 0c 83 33 4d 90 01 01 8b 55 90 01 01 89 0c 93 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}