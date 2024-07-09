
rule Trojan_BAT_DarkTortilla_AAGM_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 8c ?? 00 00 01 a2 14 20 ca 00 00 00 20 9a 00 00 00 28 ?? 00 00 2b 1f 1d 1f 0b 28 ?? 00 00 2b 13 04 1f 09 13 07 38 ?? fe ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 28 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 18 13 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}