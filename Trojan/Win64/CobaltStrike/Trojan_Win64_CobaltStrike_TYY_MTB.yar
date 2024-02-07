
rule Trojan_Win64_CobaltStrike_TYY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e8 0f 89 c0 8b 44 84 60 c1 e8 03 31 c1 41 01 c8 8b 44 24 0c 83 e8 10 89 c0 44 03 44 84 60 8b 44 24 0c 44 89 44 84 60 c7 44 24 18 a9 8a 8d 96 c7 44 24 14 8a 8a b4 19 c7 44 24 10 31 7c 58 78 e9 ac 02 00 00 } //01 00 
		$a_01_1 = {5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00  \.\PhysicalDrive0
		$a_01_2 = {51 6a 5a 73 75 } //00 00  QjZsu
	condition:
		any of ($a_*)
 
}