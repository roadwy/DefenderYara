
rule Trojan_BAT_DarkTortilla_AQSA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AQSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 74 ?? 00 00 01 14 fe 03 13 06 11 06 2c 05 16 13 0e 2b bf 1b 2b f9 09 74 ?? 00 00 01 07 74 ?? 00 00 1b 6f ?? ?? 00 0a 09 75 ?? 00 00 01 07 75 ?? 00 00 1b 6f ?? ?? 00 0a 17 13 0e 2b 95 09 75 ?? 00 00 01 6f ?? ?? 00 0a 13 07 11 07 75 ?? 00 00 01 02 16 02 8e 69 6f ?? ?? 00 0a 0a dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}