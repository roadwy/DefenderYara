
rule VirTool_Win32_Obfuscator_AGS{
	meta:
		description = "VirTool:Win32/Obfuscator.AGS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 10 03 d7 89 14 8e 41 83 c0 04 83 f9 19 7c f0 } //1
		$a_01_1 = {8b 46 58 8d 4f 68 51 8b 4e 38 2b c8 51 50 ff 56 4c } //1
		$a_03_2 = {8b 45 fc 3d 00 00 80 00 0f 86 90 01 04 8b 18 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}