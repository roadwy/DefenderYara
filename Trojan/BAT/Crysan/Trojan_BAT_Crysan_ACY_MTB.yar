
rule Trojan_BAT_Crysan_ACY_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 17 58 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 05 11 05 7e ?? 00 00 0a 28 ?? 00 00 0a 13 0c 11 0c 2c 05 ?? ?? ?? ?? ?? 11 04 11 05 06 06 8e 69 12 0e 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Crysan_ACY_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 2b 0a 00 1f 64 28 ?? 00 00 0a 00 00 09 6f ?? 00 00 0a 13 07 11 07 2d ea 11 05 73 ?? 00 00 0a 13 06 11 06 17 6f } //1
		$a_03_1 = {0a 00 11 06 28 ?? 00 00 0a 26 00 de 1d 13 08 00 72 ?? 00 00 70 11 08 6f ?? 00 00 0a 28 ?? 00 00 0a 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}