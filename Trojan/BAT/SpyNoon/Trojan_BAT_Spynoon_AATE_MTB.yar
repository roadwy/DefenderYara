
rule Trojan_BAT_Spynoon_AATE_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 72 01 00 00 70 28 90 01 01 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}