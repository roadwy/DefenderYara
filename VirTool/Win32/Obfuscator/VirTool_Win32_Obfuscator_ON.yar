
rule VirTool_Win32_Obfuscator_ON{
	meta:
		description = "VirTool:Win32/Obfuscator.ON,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 7b 3c 00 10 00 00 77 ?? 03 5b 3c 8b 43 08 } //1
		$a_01_1 = {3d 83 a7 ab 4b 75 02 } //1
		$a_03_2 = {3d 7c 58 54 b4 75 02 90 09 02 00 f7 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}