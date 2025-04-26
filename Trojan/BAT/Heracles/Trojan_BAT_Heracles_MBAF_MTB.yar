
rule Trojan_BAT_Heracles_MBAF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 11 05 6f ?? 00 00 0a 13 07 16 16 16 16 28 ?? 00 00 0a 13 08 11 07 11 08 28 ?? 00 00 0a 13 09 11 09 2c 2c 07 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 00 11 05 17 d6 13 05 11 05 11 06 31 a2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}