
rule TrojanDropper_Win32_Rustock_R{
	meta:
		description = "TrojanDropper:Win32/Rustock.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {be c0 38 00 00 3b fe 89 7d f8 0f 82 90 01 04 6a 04 68 00 30 00 00 56 53 e8 90 00 } //01 00 
		$a_01_1 = {76 1d 53 0f b7 1c 0e 03 d3 f7 c2 00 00 01 00 74 07 42 81 e2 ff ff 00 00 46 46 3b f7 72 e5 } //01 00 
		$a_03_2 = {74 14 8b 75 f0 8b f8 b9 30 0e 00 00 50 f3 a5 e8 90 01 04 eb 0c 90 00 } //01 00 
		$a_01_3 = {83 7e 04 03 75 1b 8b 46 18 38 18 75 14 8b 46 0c 38 18 74 0d ff 75 f0 50 ff 55 08 85 c0 59 } //00 00 
	condition:
		any of ($a_*)
 
}