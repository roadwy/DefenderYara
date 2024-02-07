
rule Trojan_Win64_Bumblebee_SB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 88 20 03 00 00 81 e9 90 01 04 41 90 01 06 49 8b 83 90 01 04 4c 90 01 06 49 8b 8b 90 01 04 48 8b 81 90 01 04 48 33 c7 48 89 81 90 01 04 49 8b 83 90 00 } //01 00 
		$a_00_1 = {4a 7a 47 62 45 55 38 6d } //01 00  JzGbEU8m
		$a_00_2 = {51 55 6b 30 32 34 } //00 00  QUk024
	condition:
		any of ($a_*)
 
}