
rule Trojan_BAT_NjRAT_KAAC_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 55 00 50 00 67 00 52 00 34 00 67 00 44 00 56 00 45 00 59 00 45 00 45 00 41 00 51 00 44 00 } //3 RUPgR4gDVEYEEAQD
		$a_01_1 = {49 00 67 00 41 00 41 00 52 00 67 00 42 00 41 00 41 00 4d 00 51 00 42 00 64 00 34 00 51 00 41 } //3
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}