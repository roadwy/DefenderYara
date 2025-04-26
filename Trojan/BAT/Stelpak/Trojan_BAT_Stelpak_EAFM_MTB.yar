
rule Trojan_BAT_Stelpak_EAFM_MTB{
	meta:
		description = "Trojan:BAT/Stelpak.EAFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 06 1f 28 5a 58 13 07 11 07 28 23 00 00 0a 28 24 00 00 0a 06 11 07 1e 6f 25 00 00 0a 17 8d 26 00 00 01 6f 26 00 00 0a 13 08 11 08 17 6f 27 00 00 0a 1f 43 33 4a 11 08 18 6f 27 00 00 0a 1f 53 33 3e 06 11 07 1f 14 58 28 22 00 00 0a 13 09 06 11 07 1f 10 58 28 22 00 00 0a 13 0a 11 0a 8d 1b 00 00 01 80 04 00 00 04 06 11 09 6e 7e 04 00 00 04 16 6a 11 0a 6e 28 28 00 00 0a 17 13 05 2b 0e 11 06 17 58 13 06 11 06 08 3f 70 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}