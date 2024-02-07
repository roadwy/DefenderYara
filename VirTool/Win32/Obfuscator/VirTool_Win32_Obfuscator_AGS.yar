
rule VirTool_Win32_Obfuscator_AGS{
	meta:
		description = "VirTool:Win32/Obfuscator.AGS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 10 03 d7 89 14 8e 41 83 c0 04 83 f9 19 7c f0 } //01 00 
		$a_01_1 = {8b 46 58 8d 4f 68 51 8b 4e 38 2b c8 51 50 ff 56 4c } //01 00 
		$a_03_2 = {8b 45 fc 3d 00 00 80 00 0f 86 90 01 04 8b 18 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}