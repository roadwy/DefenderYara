
rule Trojan_MacOS_Khekhe_A_MTB{
	meta:
		description = "Trojan:MacOS/Khekhe.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec f8 05 00 00 48 8b 05 ff d4 17 00 48 8b 10 e8 d0 f2 ff ff 48 8d 3d f1 dc 16 00 48 8d 35 f0 dc 16 00 48 8d 15 fd dc 16 00 31 c0 e8 23 fe ff ff 48 8d 1d 6c ff ff ff bf 01 00 00 00 48 89 de e8 6b b7 14 00 bf 1e 00 00 00 48 89 de } //1
		$a_01_1 = {48 c7 45 d0 18 00 00 00 4c 89 e7 48 8d 75 d0 e8 5e 06 00 00 48 89 df 4c 89 ee e8 8d fa ff ff ff 20 48 8d 3d 67 db 16 00 e8 a7 b4 14 00 49 89 c6 48 c7 45 d0 19 00 00 00 4c 89 e7 48 8d 75 d0 e8 2e 06 00 00 48 89 df 4c 89 ee e8 5d fa ff ff eb 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}