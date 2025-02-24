
rule Trojan_Win64_MalDrv_E_MTB{
	meta:
		description = "Trojan:Win64/MalDrv.E!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 4f 21 a2 c2 c5 7f 0d 24 6f a1 9c bf 05 99 12 07 17 60 36 35 ca 8a 57 e0 7f df 3c dd 7d 79 99 e5 e1 28 4e 4f } //1
		$a_01_1 = {ce 42 e5 0a b2 19 a5 30 df ab ac d4 be 9c 35 d2 b3 0b e1 4b e6 42 74 a8 12 5d 76 dc 06 e1 ba 5c 38 05 12 18 2d 13 44 d0 } //1
		$a_01_2 = {e2 70 e4 47 78 36 48 05 c9 ff 42 d5 b5 10 a4 45 38 4a a3 cc ed 81 d5 6b 38 4f 05 54 b3 26 4b d0 b5 ab 54 cf b6 d7 } //1
		$a_01_3 = {7e 33 5f a5 46 f5 4f 91 3d 6e 86 1d cf 56 85 34 5d 05 65 61 d9 d7 fe 95 9b 3e 51 b9 7c 23 42 c3 b5 15 0d c3 fe 07 e2 2e a4 18 c3 46 fa 5d cc 41 7a 85 62 91 2e ef eb e2 34 87 8e 06 85 0e ba e7 ae cc 15 d1 6a ea b3 a0 31 71 45 4c 08 f5 1f 2c 04 bd 7d fd } //1
		$a_01_4 = {0a ed 9e 97 2d 7a 39 55 ae 5d 28 c1 a9 26 ef 0f 98 1f 59 a8 a5 f2 e4 4a 22 8c d2 f1 b9 cb 44 6d 38 ba e3 aa 55 8e 7c 8d 2d e1 5e 1d 8a 80 b9 a3 af 27 05 e2 a1 cf 22 30 12 6a 68 17 60 c6 a1 51 27 ea 3e 5d d9 cd f5 67 eb a6 72 e7 0d 10 b5 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}