
rule Trojan_BAT_Njrat_PWA_MTB{
	meta:
		description = "Trojan:BAT/Njrat.PWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 06 4a 08 06 4a 91 02 06 4a 1f 10 5d 91 61 9c 06 06 4a 17 d6 } //5
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_3 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}