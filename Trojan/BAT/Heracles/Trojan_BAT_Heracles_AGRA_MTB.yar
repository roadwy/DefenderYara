
rule Trojan_BAT_Heracles_AGRA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AGRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 2b 36 8d ?? 00 00 01 2b 32 16 2b 33 2b 1c 2b 33 2b 34 2b 36 08 11 05 59 6f ?? 00 00 0a 13 06 11 06 2c 0c 11 05 11 06 58 13 05 11 05 08 32 df 1b 2c ed 11 04 13 07 de 36 08 2b c7 13 04 2b ca 13 05 2b c9 09 2b ca 11 04 2b c8 11 05 2b c6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}