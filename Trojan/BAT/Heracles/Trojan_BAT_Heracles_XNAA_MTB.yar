
rule Trojan_BAT_Heracles_XNAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.XNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 0a 72 15 00 00 70 28 ?? 00 00 06 72 47 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 09 20 02 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26 } //3
		$a_03_1 = {11 04 11 07 16 11 07 8e 69 28 ?? 00 00 06 20 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}