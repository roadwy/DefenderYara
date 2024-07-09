
rule Trojan_BAT_Spynoon_DVAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.DVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 2c 39 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 07 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 05 11 04 12 05 28 ?? 00 00 0a 13 07 11 07 2d c7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}