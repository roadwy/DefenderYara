
rule VirTool_Win32_Obfuscator_SF{
	meta:
		description = "VirTool:Win32/Obfuscator.SF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {3b c3 0f 84 90 01 02 00 00 90 00 } //2
		$a_01_1 = {0a c0 74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a } //2
		$a_03_2 = {8b 0c 86 39 19 0f 95 c1 51 50 8d 4d 90 01 01 e8 90 01 02 00 00 ff 45 90 01 01 83 90 01 02 63 7e bc 90 00 } //2
		$a_00_3 = {00 54 43 6e 65 72 76 65 73 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}