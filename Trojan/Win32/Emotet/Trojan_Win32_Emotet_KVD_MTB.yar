
rule Trojan_Win32_Emotet_KVD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KVD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 00 32 00 6c 00 25 00 6a 00 35 00 67 00 5a 00 43 00 4c 00 4b 00 } //2 D2l%j5gZCLK
		$a_01_1 = {4b 00 64 00 33 00 72 00 67 00 4c 00 50 00 55 00 78 00 77 00 61 00 } //2 Kd3rgLPUxwa
		$a_01_2 = {8a 4c 24 40 8b 84 24 58 03 00 00 02 d9 83 c4 30 8a 14 06 81 e3 ff 00 00 00 8a 4c 1c 14 32 d1 88 14 06 8b 84 24 2c 03 00 00 46 3b f0 } //2
		$a_01_3 = {b8 ed de 18 07 8b 4d e0 8b 55 08 8b 75 ec 81 f6 db de 18 07 01 d6 2b 45 ec 0f b6 0c 31 01 c1 88 cb 88 5d e7 } //2
		$a_01_4 = {b9 58 00 00 00 8b 94 24 dc 00 00 00 8a 5c 24 6b 20 db 88 9c 24 f3 00 00 00 81 c2 f9 3e 32 d4 89 e6 89 56 08 } //2
		$a_01_5 = {8b 45 c4 8b 4d ec 81 f1 6f a7 da 23 01 c8 89 45 c4 b8 f1 a7 da 23 2b 45 ec 39 45 c4 0f 85 } //2
		$a_01_6 = {8b 45 08 8b 4d 10 0f b6 d3 03 c1 8a 94 15 8c fe ff ff 30 10 41 3b 4d 0c 89 4d 10 0f 8c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=2
 
}