
rule Trojan_BAT_Crysan_PGZ_MTB{
	meta:
		description = "Trojan:BAT/Crysan.PGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 91 08 09 08 8e 69 5d 91 61 d2 9c 08 09 08 8e 69 5d 08 09 08 8e 69 5d 91 17 58 20 ?? ?? ?? 00 5d d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d c8 } //10
		$a_01_1 = {00 02 28 08 00 00 0a 0a 06 8e 69 } //1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}