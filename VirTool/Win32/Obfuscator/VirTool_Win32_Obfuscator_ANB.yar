
rule VirTool_Win32_Obfuscator_ANB{
	meta:
		description = "VirTool:Win32/Obfuscator.ANB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 ba 4d 5a 66 ad 66 33 d0 74 08 81 ee 90 01 04 eb 90 00 } //01 00 
		$a_03_1 = {0f c8 03 c2 5a ab 83 e9 90 09 07 00 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}