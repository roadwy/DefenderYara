
rule Adware_MacOS_Adload_A_MTB{
	meta:
		description = "Adware:MacOS/Adload.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 00 d7 1d 0b e6 66 00 91 1e 0c c1 63 00 ee 1f 80 03 dc 66 00 86 23 0b bc 66 00 d5 23 1e fb 65 00 f3 23 0b f9 65 00 c2 24 08 d4 66 00 d2 24 08 d2 66 00 f6 24 08 b7 63 00 a7 25 2c 92 64 00 d8 25 13 8d 64 00 eb 25 13 ee 63 00 ca 28 0c d4 66 00 dd 28 08 f4 62 } //1
		$a_01_1 = {da 01 35 bd 01 c6 01 66 6a 6a 2e 3e 3d af 02 96 05 4d 91 03 88 02 3e 1e 3e aa 01 0a 1c 84 02 94 02 fc 01 c0 01 ac 04 a6 05 48 91 05 31 26 2c 36 26 26 2c 9e 01 30 38 e2 02 26 42 5a fe 02 7e 86 01 7a 82 01 84 01 8c 01 20 0e 0e 26 2c 26 2c 0a 1c 0e 0e 4e 56 58 60 ba 04 a2 04 6e 76 76 7e 4e 72 50 48 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}