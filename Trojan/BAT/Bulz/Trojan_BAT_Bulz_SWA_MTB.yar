
rule Trojan_BAT_Bulz_SWA_MTB{
	meta:
		description = "Trojan:BAT/Bulz.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 0a 1f 28 5a 58 13 0b 28 20 00 00 0a 11 04 11 0b 1e 6f 21 00 00 0a 17 8d 28 00 00 01 6f 22 00 00 0a 13 0c 28 20 00 00 0a 11 0c 6f 23 00 00 0a 28 24 00 00 0a 72 16 01 00 70 28 25 00 00 0a 39 3c 00 00 00 11 04 11 0b 1f 14 58 28 1f 00 00 0a 13 0d 11 04 11 0b 1f 10 58 28 1f 00 00 0a 13 0e 11 0e 8d 1c 00 00 01 0c 11 04 11 0d 6e 08 16 6a 11 0e 6e 28 26 00 00 0a 17 13 09 38 0f 00 00 00 11 0a 17 58 13 0a 11 0a 11 06 3f 6f ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}