
rule Trojan_BAT_SpyNoon_AMBF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0e 11 0f 61 13 10 07 11 0b 11 10 11 0d 59 11 09 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}