
rule Adware_MacOS_Pirrit_J_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 05 52 cf 0a 00 8b 0d 50 cf 0a 00 21 c8 25 92 33 61 18 2d 33 42 5f ee 8b 0d 1a 94 0b 00 89 4d a8 b9 21 b8 32 d5 ba 9e 6f 8c 80 0f 45 d1 89 55 a0 48 8b 35 48 d1 0a 00 89 85 f4 fe ff ff ff e6 } //1
		$a_01_1 = {c7 05 63 50 0b 00 01 00 00 00 48 89 e0 48 89 c1 48 83 c1 f0 48 89 cc 48 89 e1 48 83 c1 f0 48 89 cc 48 8b 4d f8 48 89 48 f0 48 8b 05 e9 8d 0a 00 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}