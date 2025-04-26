
rule Trojan_BAT_XWorm_NIT_MTB{
	meta:
		description = "Trojan:BAT/XWorm.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 3b 00 00 0a 20 e8 03 00 00 20 88 13 00 00 6f 3c 00 00 0a 28 21 00 00 0a 7e 0f 00 00 04 2d 0a 28 1e 00 00 06 28 18 00 00 06 7e 16 00 00 04 6f 3d 00 00 0a 26 17 2d c8 } //2
		$a_01_1 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //1 AES_Decryptor
		$a_01_2 = {41 6e 74 69 76 69 72 75 73 } //1 Antivirus
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}