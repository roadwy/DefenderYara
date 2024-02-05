
rule VirTool_Win32_Obfuscator_BZB{
	meta:
		description = "VirTool:Win32/Obfuscator.BZB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 4d 75 11 33 c9 8a 0d 90 01 04 83 f9 5a 0f 84 8e 00 00 00 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 33 c9 8a 88 90 01 04 83 f1 30 8b 55 fc 88 8a 90 01 04 8b 45 fc 33 c9 8a 88 90 01 04 83 e9 30 8b 55 fc 88 8a 90 01 04 d9 05 90 01 04 d8 05 90 01 04 d8 05 90 01 04 d8 05 90 01 04 d9 1d 90 01 04 eb 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}