
rule Trojan_Win64_Ransodoppo_LK_MTB{
	meta:
		description = "Trojan:Win64/Ransodoppo.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 08 48 8b 05 90 01 03 00 0f b6 14 38 03 d1 8b 0d 90 01 03 00 48 8b 05 90 01 03 00 88 14 08 8b 05 90 01 03 00 83 c0 01 89 05 90 00 } //01 00 
		$a_01_1 = {03 14 24 8b 0c 24 48 8b 44 24 20 89 14 08 8b 14 24 8b 0c 24 81 c1 e9 03 00 00 48 8b 44 24 20 8b 14 10 33 d1 8b 0c 24 48 8b 44 24 20 89 14 08 eb b2 } //00 00 
	condition:
		any of ($a_*)
 
}