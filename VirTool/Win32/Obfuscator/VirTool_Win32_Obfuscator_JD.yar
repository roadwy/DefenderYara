
rule VirTool_Win32_Obfuscator_JD{
	meta:
		description = "VirTool:Win32/Obfuscator.JD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fb 00 50 80 7c 0f 84 90 01 04 81 fb 2e 26 00 70 0f 84 90 00 } //01 00 
		$a_01_1 = {96 59 87 fd 74 1c 83 c7 02 e2 dc e9 } //01 00 
		$a_03_2 = {66 ad 86 c4 66 33 45 90 01 01 83 6d 90 01 02 ff 45 90 01 01 66 ab e2 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}