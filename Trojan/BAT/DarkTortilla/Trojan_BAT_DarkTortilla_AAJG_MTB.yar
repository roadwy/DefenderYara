
rule Trojan_BAT_DarkTortilla_AAJG_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1d 13 07 38 ?? fe ff ff 1c 13 07 38 ?? fe ff ff 07 17 d6 0b 1e 13 07 38 ?? fe ff ff 07 08 fe 04 13 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}