
rule Trojan_BAT_Crysan_AAKU_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 09 16 11 09 8e 69 28 ?? 00 00 06 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 11 02 28 ?? 00 00 06 13 07 20 02 00 00 00 38 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}