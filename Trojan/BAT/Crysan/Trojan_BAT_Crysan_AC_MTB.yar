
rule Trojan_BAT_Crysan_AC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 31 00 00 01 0a 02 8e 69 17 59 0b 16 0c 2b 0e 06 08 02 07 91 9c 07 17 59 0b 08 17 58 0c 08 06 8e 69 32 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Crysan_AC_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 7e ?? 00 00 0a a2 25 18 09 a2 25 19 17 8c ?? 00 00 01 a2 13 04 14 13 05 07 28 ?? 00 00 0a 72 ?? 02 00 70 6f ?? 00 00 0a 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Crysan_AC_MTB_3{
	meta:
		description = "Trojan:BAT/Crysan.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0b 2b 24 00 11 09 11 0b 58 06 11 0b 58 47 08 11 0b 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 52 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0c 11 0c 2d cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}