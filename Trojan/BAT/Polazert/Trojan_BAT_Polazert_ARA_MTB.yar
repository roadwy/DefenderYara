
rule Trojan_BAT_Polazert_ARA_MTB{
	meta:
		description = "Trojan:BAT/Polazert.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 47 06 09 91 61 d2 52 09 17 58 06 8e 69 32 04 16 0d 2b 04 09 17 58 0d 08 17 58 0c 08 07 8e 69 32 d7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Polazert_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Polazert.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 0c 17 0d 2b 1c 00 07 08 5d 16 6a fe 01 16 fe 01 13 04 11 04 2d 05 00 16 0d 2b 15 08 17 6a 58 0c 00 08 08 5a 07 fe 02 16 fe 01 13 04 11 04 2d d5 08 17 6a fe 04 16 fe 01 13 04 11 04 2d 02 2b 0b 07 17 6a 58 0b 00 17 13 04 2b 95 } //00 00 
	condition:
		any of ($a_*)
 
}