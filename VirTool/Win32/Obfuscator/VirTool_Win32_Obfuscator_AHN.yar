
rule VirTool_Win32_Obfuscator_AHN{
	meta:
		description = "VirTool:Win32/Obfuscator.AHN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 38 ff 74 13 8b 30 83 c0 04 8b 38 83 c0 04 8b 08 83 c0 04 f3 a4 eb e8 68 90 01 04 c3 90 09 10 00 e8 00 00 00 00 58 2d 90 01 04 05 90 00 } //01 00 
		$a_03_1 = {66 33 c0 66 81 38 4d 5a 74 07 2d 00 00 01 00 eb f2 89 85 90 01 04 8b 85 90 01 04 66 8b 48 3c 66 89 8d 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}