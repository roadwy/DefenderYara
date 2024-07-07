
rule VirTool_Win32_Obfuscator_AAB{
	meta:
		description = "VirTool:Win32/Obfuscator.AAB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 01 31 c0 8b 14 c7 41 04 24 83 c4 10 c7 41 08 40 ff e2 90 } //1
		$a_03_1 = {4a 81 fa 6b 6c 33 32 74 90 01 01 53 81 fa 6b 6f 72 65 5b 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}