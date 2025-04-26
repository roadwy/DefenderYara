
rule Trojan_BAT_Spynoon_HVAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.HVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 1f 16 6a 5d d4 91 61 28 ?? 00 00 06 07 11 07 08 6a 5d d4 91 28 ?? 00 00 06 59 11 08 58 11 08 5d 28 ?? 00 00 06 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}