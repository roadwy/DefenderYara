
rule VirTool_BAT_Injector_EC{
	meta:
		description = "VirTool:BAT/Injector.EC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 0e 00 00 0a 28 0f 00 00 0a 6f 10 00 00 0a 28 11 00 00 0a 17 8d 10 00 00 01 13 05 11 05 16 1f 7c 9d 11 05 6f 12 00 00 0a a2 09 28 13 00 00 0a 6f 14 00 00 0a 14 11 04 6f 15 00 00 0a } //01 00 
		$a_01_1 = {20 5e 01 00 00 0a 28 16 00 00 0a 03 6f 17 00 00 0a 0b 16 0c 2b 31 02 08 8f 14 00 00 01 25 71 14 00 00 01 07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 14 00 00 01 08 17 58 0c 08 02 8e 69 32 c9 } //01 00 
		$a_00_2 = {7c 00 31 00 2e 00 30 00 2e 00 32 00 7c 00 } //00 00  |1.0.2|
	condition:
		any of ($a_*)
 
}