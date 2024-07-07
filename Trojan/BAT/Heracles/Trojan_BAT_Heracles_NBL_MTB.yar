
rule Trojan_BAT_Heracles_NBL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 fe 0c 16 00 fe 0c 01 00 fe 0c 16 00 91 20 8b 45 9f 04 20 92 aa 4d 16 61 65 20 3a c7 78 ef 58 66 20 6e dd 3d 04 61 20 01 00 00 00 63 20 01 00 00 00 62 65 20 03 00 00 00 63 20 7a 00 13 fb 61 61 d2 9c } //3
		$a_01_1 = {fe 0c 02 00 fe 0c 01 00 fe 0c 02 00 fe 0c 01 00 93 20 e7 b7 17 d2 20 47 0f 44 13 61 20 05 00 00 00 63 20 43 9d 0a fe 61 61 fe 09 00 00 61 d1 9d } //3
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_3 = {73 65 74 5f 4b 65 79 } //set_Key  1
		$a_80_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  1
		$a_80_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //CreateEncryptor  1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=10
 
}