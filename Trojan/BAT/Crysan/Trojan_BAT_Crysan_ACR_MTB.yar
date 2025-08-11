
rule Trojan_BAT_Crysan_ACR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a de 03 26 de 00 72 ?? 00 00 70 0a 72 ?? 00 00 70 06 28 ?? 00 00 0a 26 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Crysan_ACR_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d 16 00 06 16 6f ?? 00 00 0a 0c 16 0d 2b 1a 16 2d b5 08 09 91 13 04 00 07 11 04 6f ?? 00 00 0a 00 00 09 19 2c 04 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Crysan_ACR_MTB_3{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 06 73 12 00 00 0a 07 6f ?? 00 00 0a 00 73 14 00 00 0a 0d 09 20 e8 03 00 00 20 b8 0b 00 00 6f ?? 00 00 0a 13 04 11 04 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Crysan_ACR_MTB_4{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 01 00 00 06 0a 06 16 28 02 00 00 06 26 28 04 00 00 06 6f 05 00 00 0a 2a } //1
		$a_01_1 = {7d 04 00 00 04 12 00 7b 05 00 00 04 0b 12 01 12 00 28 02 00 00 2b 12 00 7c 05 00 00 04 28 28 00 00 0a 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Crysan_ACR_MTB_5{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 73 11 06 6f ?? 00 00 0a 74 ?? 00 00 01 13 07 00 1b 28 ?? 00 00 0a 00 07 11 07 6f ?? 00 00 0a 6f ?? 00 00 0a 13 08 11 08 2c 49 00 1f 0e 28 ?? 00 00 0a 00 72 ?? 04 00 70 11 04 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}