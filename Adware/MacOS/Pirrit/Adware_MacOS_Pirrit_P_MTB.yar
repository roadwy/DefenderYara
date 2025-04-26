
rule Adware_MacOS_Pirrit_P_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.P!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 b7 6d 44 30 3d da 6c 00 00 41 b0 e0 44 30 05 d1 6c 00 00 b0 94 30 05 ca 6c 00 00 80 35 c4 6c 00 00 89 80 35 be 6c 00 00 6a 80 35 bb 6c 00 00 30 41 b2 77 44 30 15 b2 6c 00 00 b0 b0 30 05 ab 6c 00 00 80 35 a5 6c 00 00 d7 80 35 9f 6c 00 00 ef b1 45 30 0d 98 6c 00 00 80 35 93 6c 00 00 58 30 05 8e 6c 00 00 } //1
		$a_01_1 = {80 35 a7 32 00 00 48 80 35 a1 32 00 00 d6 80 35 9b 32 00 00 c9 80 35 95 32 00 00 bb 80 35 8f 32 00 00 c3 80 35 89 32 00 00 e0 80 35 83 32 00 00 b7 80 35 7d 32 00 00 14 ff 25 60 37 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}