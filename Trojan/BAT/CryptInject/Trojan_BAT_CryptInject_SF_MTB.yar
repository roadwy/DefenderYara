
rule Trojan_BAT_CryptInject_SF_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e b7 17 da 17 d6 8d 90 01 01 00 00 01 0a 16 02 8e b7 17 da 0d 0c 38 90 01 01 00 00 00 20 90 01 04 20 90 01 04 61 25 fe 0e 04 00 20 90 01 01 00 00 00 5e 45 90 01 01 00 00 00 90 01 01 00 00 00 90 01 01 00 00 00 90 01 01 00 00 00 90 01 01 ff ff ff 90 02 0a 00 00 00 90 02 10 06 08 02 08 91 03 08 03 8e b7 5d 91 61 9c 90 02 10 08 17 d6 0c 90 00 } //1
		$a_01_1 = {28 1a 00 00 0a 11 0e 11 04 28 d6 00 00 06 6f 1b 00 00 0a 0b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_CryptInject_SF_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 30 05 00 ba 00 00 00 02 00 00 11 02 8e b7 17 d6 8d 03 00 00 01 0a 16 8c 04 00 00 01 28 02 00 00 0a 26 02 02 8e b7 17 da 91 1f 70 61 0b 28 03 00 00 0a 03 6f 04 00 00 0a 0c 16 8c 04 00 00 01 28 02 00 00 0a 26 16 8c 04 00 00 01 28 02 00 00 0a 26 16 02 8e b7 17 da 0d 13 04 2b 2d 06 11 04 02 11 04 91 07 61 08 11 05 91 61 b4 9c 11 05 03 6f 05 00 00 0a 17 da 33 05 16 13 05 2b 06 11 05 17 d6 13 05 11 04 17 d6 13 04 11 04 09 31 ce 16 8c 04 00 00 01 28 02 00 00 0a 26 06 74 08 00 00 01 02 8e b7 18 da 17 d6 8d 03 00 00 01 28 06 00 00 0a 74 01 00 00 1b 0a 16 8c 04 00 00 01 28 02 00 00 0a 26 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}