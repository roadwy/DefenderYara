
rule Trojan_BAT_AzorultCrypt_SK_MTB{
	meta:
		description = "Trojan:BAT/AzorultCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 6f 7b 00 00 0a 0a 16 0b 38 43 00 00 00 06 07 9a 0c 00 08 6f 7c 00 00 0a 72 c6 19 00 70 28 7d 00 00 0a 0d 09 39 22 00 00 00 00 08 72 c6 19 00 70 20 00 01 00 00 14 14 14 6f 7e 00 00 0a 26 00 28 7f 00 00 0a 6f 80 00 00 0a 00 00 00 07 17 58 0b 07 06 8e 69 3f b4 ff ff ff 2a } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}