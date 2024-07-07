
rule Trojan_BAT_CobaltStrike_AAMI_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.AAMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 25 17 6f 90 01 01 00 00 0a 00 25 18 6f 90 01 01 00 00 0a 00 0d 09 6f 90 01 01 00 00 0a 13 04 11 04 08 16 08 8e 69 6f 90 01 01 00 00 0a 13 05 28 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a 13 0a de 0b 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}