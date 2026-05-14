
rule Trojan_BAT_Spynoon_ADRB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ADRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 03 11 04 6f ?? 00 00 0a 13 07 38 ?? ?? 00 00 11 0a 20 9d 00 00 00 61 d2 13 0a 38 ?? fe ff ff 00 38 ?? ?? 00 00 38 ?? ?? 00 00 11 0a 11 00 18 58 28 ?? 00 00 06 13 0a 38 ?? ?? 00 00 11 18 39 ?? 00 00 00 38 ?? ?? 00 00 00 12 08 28 ?? 00 00 0a 13 23 38 ?? 00 00 00 11 0a 28 ?? 00 00 06 13 0a 38 ?? ?? 00 00 00 11 03 02 6f ?? 00 00 0a fe 04 16 fe 01 13 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}