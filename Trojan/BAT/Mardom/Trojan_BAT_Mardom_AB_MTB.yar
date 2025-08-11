
rule Trojan_BAT_Mardom_AB_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 0b 06 07 16 1a 6f 0c 00 00 0a 26 07 16 28 0d 00 00 0a 0c 06 16 73 0e 00 00 0a } //2
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}