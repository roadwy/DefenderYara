
rule Trojan_Win64_CobaltStrike_ML_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 8b 04 02 49 83 c2 04 48 8b 05 90 01 04 45 0f af 81 8c 00 00 00 8b 88 60 01 00 00 81 c1 90 01 04 41 03 89 f8 00 00 00 41 8b d0 41 31 49 34 8b 05 90 01 04 35 62 93 11 00 c1 ea 10 41 01 81 94 00 00 00 48 8b 05 90 01 04 48 63 88 a4 00 00 00 49 8b 81 e0 00 00 00 88 14 01 90 00 } //01 00 
		$a_01_1 = {43 50 48 79 6c 49 32 } //00 00  CPHylI2
	condition:
		any of ($a_*)
 
}