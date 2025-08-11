
rule Adware_MacOS_Pirrit_W_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.W!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 05 42 29 02 00 8d 0c 00 80 e1 a8 04 54 0f b6 15 32 29 02 00 66 0f 6e ca 0f b6 c0 66 0f 3a 20 c8 01 66 0f 6e 05 21 29 02 00 66 0f 6f d1 66 0f 3a 20 15 11 29 02 00 02 66 0f 3a 20 15 08 29 02 00 03 66 0f 62 d0 0f b6 c1 66 0f 6f 05 dc a7 00 00 66 0f ef d0 66 0f 3a 20 c0 01 66 0f f8 c8 0f 28 05 c7 40 00 00 66 0f 38 10 ca 66 0f d6 0d e2 28 02 00 0f b7 05 df 25 02 00 66 0f 6e c8 66 0f 6e 05 d6 25 02 00 8a 05 d4 25 02 00 89 c1 f6 d1 0c 1b 66 0f 3a 20 0d bf 25 02 00 02 80 c9 e4 66 0f 60 c1 66 0f 38 00 05 31 40 00 00 20 c1 } //1
		$a_01_1 = {66 0f 3a 20 c1 03 80 e2 64 0f b6 c0 66 0f 3a 20 c0 04 0f b6 c2 66 0f 3a 20 c0 05 66 0f f8 c8 0f 28 05 0b 7f 03 00 66 0f 38 10 ca 66 0f d6 0d e3 78 04 00 8a 05 c5 78 04 00 34 6c 88 05 dd 78 04 00 8a 05 b8 78 04 00 34 9e 88 05 d0 78 04 00 8a 05 ab 78 04 00 34 c0 88 05 c3 78 04 00 8a 05 9e 78 04 00 8d 0c 00 80 e1 8e 28 c8 04 c7 88 05 ae 78 04 00 66 0f 6e 0d b7 78 04 00 8a 15 b5 78 04 00 8d 04 12 80 c2 73 f3 0f 7e 05 aa 78 04 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}