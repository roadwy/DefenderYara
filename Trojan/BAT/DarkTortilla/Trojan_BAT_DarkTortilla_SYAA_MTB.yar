
rule Trojan_BAT_DarkTortilla_SYAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 75 ?? 00 00 1b 6f ?? 00 00 0a 17 da 0c 1d 13 05 2b ab 16 0d 1b 13 05 2b a4 07 75 ?? 00 00 1b 09 07 75 ?? 00 00 1b 09 6f ?? 00 00 0a 1f 33 61 b4 6f ?? 00 00 0a 1c 13 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}