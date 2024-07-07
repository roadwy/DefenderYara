
rule Trojan_Win32_Sdum_DS_MTB{
	meta:
		description = "Trojan:Win32/Sdum.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 7f ec 36 d8 89 dc b2 bf 59 8c 50 f1 03 85 01 c4 43 2e a4 7c 6b 07 af 67 18 ba d6 e0 ef d1 d7 01 84 83 a2 5d 2a 11 38 65 a4 fb 5b 30 42 84 c2 0f 3d 28 f7 fd fa 4e 4b e6 65 0a c9 95 dd de f0 } //1
		$a_01_1 = {0e d3 21 71 a0 10 ea 03 c2 72 ca 3e 02 00 c2 43 63 01 29 50 3a db 89 e3 58 36 80 c1 ed 6d d1 2b 1e 45 9b 21 6a da 51 19 d6 3d 1c 0b 17 44 cb 49 14 3d b3 40 86 f0 f6 e7 29 ea 48 79 5c ba a6 d9 b0 50 3d f7 e9 11 78 c6 71 } //1
		$a_01_2 = {55 7e 80 52 48 ce 82 5b ce e4 39 3e 55 88 d3 ca 81 7f ec 36 d8 89 dc b2 bf 59 8c 50 f1 03 85 01 c4 43 2e a4 7c 6b 07 af 67 18 ba d6 e0 ef d1 d7 01 84 83 a2 5d 2a 11 38 65 a4 fb 5b 30 42 84 c2 } //1
		$a_01_3 = {20 41 22 51 5e b1 47 eb b9 dd 38 4c 21 30 cb 2a f3 55 4c 6d 46 ba 82 09 d9 44 c0 33 15 58 be 56 d3 94 79 69 d1 de 58 c8 2a 57 78 46 0d 6d 21 b4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}