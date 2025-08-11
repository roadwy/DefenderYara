
rule Trojan_BAT_DarkComet_ACD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 13 06 0d 2b 47 03 08 09 6f ?? 00 00 0a 13 04 11 04 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 12 04 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}