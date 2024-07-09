
rule Trojan_BAT_Rozena_FGAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.FGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 06 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 20 00 04 00 00 8d ?? 00 00 01 13 04 2b 0b 09 11 04 16 11 05 6f ?? 00 00 0a 08 11 04 16 11 04 8e 69 6f ?? 00 00 0a 25 13 05 16 30 e2 09 6f ?? 00 00 0a 13 06 de 28 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}