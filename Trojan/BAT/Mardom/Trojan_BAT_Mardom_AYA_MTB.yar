
rule Trojan_BAT_Mardom_AYA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {1b 2c 3b 00 16 2d 08 2b 15 2b 16 1a 2d 1a 26 2b 1a 2b 1b 2b 1c 1b 2d 20 26 16 2d f3 de 20 02 2b e8 28 04 00 00 06 2b e3 0a 2b e4 06 2b e3 02 2b e2 28 06 00 00 06 2b dd 0b 2b de 26 de c2 1b 2c bf } //2
		$a_01_1 = {24 61 35 38 37 37 61 35 64 2d 31 38 32 38 2d 34 62 33 64 2d 38 62 66 38 2d 34 38 61 61 65 36 31 32 30 64 31 61 } //1 $a5877a5d-1828-4b3d-8bf8-48aae6120d1a
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}