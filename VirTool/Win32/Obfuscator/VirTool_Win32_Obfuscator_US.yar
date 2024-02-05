
rule VirTool_Win32_Obfuscator_US{
	meta:
		description = "VirTool:Win32/Obfuscator.US,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 74 18 78 58 } //01 00 
		$a_01_1 = {74 8f fc 03 f3 52 } //01 00 
		$a_01_2 = {ff 74 8f fc 5e } //01 00 
		$a_01_3 = {58 0f b7 7c 4a fe 03 1c b8 } //01 00 
		$a_01_4 = {33 55 fc 33 ca 68 00 00 00 00 8f 43 0c } //01 00 
		$a_03_5 = {74 13 49 75 90 01 01 58 c1 e0 90 01 01 c1 e0 90 01 01 d1 e0 5e 90 00 } //01 00 
		$a_03_6 = {0c 20 c1 c2 90 01 01 c1 c2 90 01 01 c1 ca 90 01 01 c1 c2 90 01 01 32 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}