
rule TrojanDropper_Win32_Cutwail_AH{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b c8 64 8b 1d 18 00 00 00 85 c9 74 01 42 } //02 00 
		$a_01_1 = {8f 45 f8 09 03 83 e9 04 7e 14 03 45 f8 03 45 fc } //01 00 
		$a_01_2 = {25 00 00 ff ff c1 e2 09 } //01 00 
		$a_01_3 = {8b f0 83 c6 c4 8b 08 8b 4c 31 50 } //00 00 
	condition:
		any of ($a_*)
 
}