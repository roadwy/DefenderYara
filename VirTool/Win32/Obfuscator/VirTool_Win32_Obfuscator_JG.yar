
rule VirTool_Win32_Obfuscator_JG{
	meta:
		description = "VirTool:Win32/Obfuscator.JG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b f0 03 76 3c 81 c6 a0 00 00 00 8b 36 81 fe 00 00 06 00 77 90 01 01 cc 90 00 } //1
		$a_03_1 = {8b d8 03 5b 3c 81 c3 a0 00 00 00 8b 1b 81 fb 00 00 06 00 77 90 01 01 cc 90 00 } //1
		$a_03_2 = {8b d0 03 52 3c 81 c2 a0 00 00 00 8b 12 81 fa 00 00 06 00 77 90 01 01 cc 90 00 } //1
		$a_03_3 = {8b f8 03 7f 3c 81 c7 a0 00 00 00 8b 3f 81 ff 00 00 06 00 77 90 01 01 cc 90 00 } //1
		$a_03_4 = {8b c8 03 49 3c 81 c1 a0 00 00 00 8b 09 81 f9 00 00 06 00 77 90 01 01 cc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}