
rule Trojan_BAT_Spynoon_CUAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.CUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0b 91 61 08 11 08 07 20 88 00 00 00 58 5d 91 11 07 58 11 07 5d 59 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}