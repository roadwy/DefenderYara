
rule Trojan_BAT_Spynoon_AAUT_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 07 11 07 07 8e 69 6a 5d d4 11 08 20 00 01 00 00 5d d2 9c 00 11 07 17 6a 58 13 07 11 07 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 09 11 09 2d a2 } //00 00 
	condition:
		any of ($a_*)
 
}