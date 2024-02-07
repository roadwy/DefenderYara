
rule VirTool_Win32_Obfuscator_AQW_Upatre{
	meta:
		description = "VirTool:Win32/Obfuscator.AQW!Upatre,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 24 2f 00 00 00 ff 04 24 ff 04 24 58 05 0b 00 00 00 ff 34 07 58 03 c7 6a 1e 5e 83 ee 02 } //01 00 
		$a_01_1 = {8a 16 5e 58 49 fe ca 8a d8 fe cb 50 8b c3 25 01 00 00 00 32 d0 b8 0d 00 00 00 32 d0 } //01 00 
		$a_03_2 = {6a 00 6a 00 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 83 ec 04 c7 04 24 00 00 00 80 81 c7 7d 2b 00 00 83 ec 04 89 3c 24 33 db 81 c3 90 01 04 be 90 01 04 ff 16 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}