
rule Trojan_BAT_Spynoon_GNAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.GNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 1f 00 7e ?? 00 00 04 11 04 7e ?? 00 00 04 11 04 91 20 ?? ?? 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? 00 00 04 8e 69 fe 04 13 05 11 05 2d d0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}