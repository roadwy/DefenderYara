
rule Adware_MacOS_Pirrit_M_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.M!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 81 e6 00 01 00 00 41 09 d6 c1 ef 13 81 e7 00 10 00 00 44 09 f7 8b 55 98 31 d6 31 f1 89 c8 8b 5d 9c 31 d8 41 31 d9 8b 5d a0 31 de 44 31 ce 66 89 75 b8 66 89 4d ba 66 89 55 bc 44 31 e2 31 fa 44 31 ca 89 ce 44 31 e6 31 f9 31 df 66 89 55 be 66 89 4d c0 31 c7 66 89 45 c2 66 89 75 c4 66 89 7d c6 } //1
		$a_01_1 = {48 8b bd d8 fe ff ff 4c 89 f6 48 89 8d 38 fe ff ff 48 89 ca e8 1a cb 0c 00 48 8b 85 60 fb ff ff 48 89 85 40 fe ff ff 8b 85 f8 fb ff ff 89 85 a4 fe ff ff f2 0f 10 85 fc fb ff ff 0f 29 85 60 fc ff ff 48 8b 85 78 fb ff ff b9 08 00 00 00 48 89 8d 30 ff ff ff b9 08 00 00 00 48 89 8d c8 fe ff ff 48 89 85 a8 fe ff ff 48 85 c0 0f 84 f6 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}