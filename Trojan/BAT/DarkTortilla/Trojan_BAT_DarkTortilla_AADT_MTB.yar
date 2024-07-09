
rule Trojan_BAT_DarkTortilla_AADT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1e 13 07 38 ?? fe ff ff 1c 13 07 38 ?? fe ff ff 07 17 d6 0b 17 13 07 38 ?? fe ff ff 07 08 fe 04 13 05 11 05 2d 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}