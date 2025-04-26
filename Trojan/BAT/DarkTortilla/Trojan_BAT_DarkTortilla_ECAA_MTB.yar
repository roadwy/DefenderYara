
rule Trojan_BAT_DarkTortilla_ECAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ECAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 1e 28 ?? 00 00 0a 7e ?? 00 00 04 2c 07 7e ?? 00 00 04 2b 16 7e ?? 00 00 04 fe ?? ?? 01 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}