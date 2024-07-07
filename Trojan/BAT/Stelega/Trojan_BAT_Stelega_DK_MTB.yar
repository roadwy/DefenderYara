
rule Trojan_BAT_Stelega_DK_MTB{
	meta:
		description = "Trojan:BAT/Stelega.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0c 08 2d cf 90 00 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {78 6f 72 65 64 53 74 72 69 6e 67 } //1 xoredString
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}