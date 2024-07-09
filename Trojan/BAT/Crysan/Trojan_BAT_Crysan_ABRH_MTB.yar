
rule Trojan_BAT_Crysan_ABRH_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ABRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0e 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 0c dd ?? 00 00 00 26 de d4 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}