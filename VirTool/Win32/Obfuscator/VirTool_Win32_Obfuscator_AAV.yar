
rule VirTool_Win32_Obfuscator_AAV{
	meta:
		description = "VirTool:Win32/Obfuscator.AAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f3 0f 53 c1 c7 45 } //01 00 
		$a_03_1 = {0f 10 05 04 90 01 03 c7 45 90 01 05 90 03 02 02 c7 45 8b 55 90 00 } //01 00 
		$a_03_2 = {0f 11 05 04 90 01 03 c7 45 90 00 } //01 00 
		$a_03_3 = {33 d2 81 7d 90 01 05 0f 9e c2 90 00 } //01 00 
		$a_03_4 = {33 d2 3b c1 0f 90 03 01 01 95 9f c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}