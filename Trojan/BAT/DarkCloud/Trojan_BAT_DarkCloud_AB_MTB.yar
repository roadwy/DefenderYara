
rule Trojan_BAT_DarkCloud_AB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 13 06 07 09 8e 69 11 06 16 11 06 8e 69 28 54 04 00 0a 00 11 05 11 06 16 11 06 8e 69 6f } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}