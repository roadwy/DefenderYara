
rule Trojan_BAT_QuasarRAT_BAK_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 08 11 07 11 08 91 20 95 00 00 00 61 d2 9c 11 08 17 58 13 08 11 08 11 07 8e 69 32 e1 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}