
rule Trojan_BAT_Heracles_ABOJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABOJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 90 01 03 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 32 e4 90 0a 40 00 28 90 01 03 06 0a 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 00 } //6
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=8
 
}