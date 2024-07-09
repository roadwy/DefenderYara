
rule Trojan_BAT_DarkKomet_AATY_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.AATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 13 04 11 04 11 05 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 02 28 ?? 00 00 0a 0b 09 07 16 07 8e b7 6f ?? 00 00 0a 09 6f ?? 00 00 0a 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 10 00 de 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}