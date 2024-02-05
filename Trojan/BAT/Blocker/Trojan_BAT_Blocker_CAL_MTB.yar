
rule Trojan_BAT_Blocker_CAL_MTB{
	meta:
		description = "Trojan:BAT/Blocker.CAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 08 16 16 02 74 90 01 01 00 00 1b 08 91 11 08 28 90 01 01 00 00 0a 18 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 09 07 1a 9a 74 90 01 01 00 00 1b 08 11 09 28 90 01 01 00 00 0a 9c 08 17 d6 0c 00 08 8c 90 01 01 00 00 01 07 19 9a 16 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 0a 11 0a 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}