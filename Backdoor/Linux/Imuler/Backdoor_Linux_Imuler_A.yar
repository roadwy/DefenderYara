
rule Backdoor_Linux_Imuler_A{
	meta:
		description = "Backdoor:Linux/Imuler.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 fe 07 7e 11 8b 03 a3 c0 34 01 00 8b 43 04 a3 c4 34 01 00 eb 14 } //1
		$a_01_1 = {f7 d0 21 c2 81 e2 80 80 80 80 74 e9 89 d0 c1 e8 10 f7 c2 80 80 00 00 0f 44 d0 8d 41 02 0f 45 c1 00 d2 83 d8 03 c7 00 2f 63 67 69 c7 40 04 2d 6d 61 63 c7 40 08 2f 32 77 6d } //1
		$a_01_2 = {8b 01 83 c1 04 8d 90 ff fe fe fe f7 d0 21 c2 81 e2 80 80 80 80 74 e9 89 d0 c1 e8 10 f7 c2 80 80 00 00 0f 44 d0 8d 41 02 0f 44 c8 00 d2 83 d9 03 81 e9 60 32 01 00 } //1
		$a_01_3 = {89 c3 ba ab aa aa 2a f7 ea d1 fa 89 d9 c1 f9 1f 29 ca 8d 14 52 c1 e2 02 29 d3 8d 43 01 89 04 24 e8 7e 06 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}