
rule Trojan_Win64_MalLoadz_B_MTB{
	meta:
		description = "Trojan:Win64/MalLoadz.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 69 6f 6e 2e 00 00 00 00 fa 9b 37 cc 17 fa 83 20 c7 72 07 da 83 20 c7 72 07 ee 8a 30 c7 17 ce aa 10 e7 17 d8 ba 6f ab 5e 2f 3e 61 9d bb 71 a9 3b a6 89 cc a6 31 12 bc 14 91 9e d1 86 45 b6 1e 40 5d 8d d2 2f 12 88 11 4e 45 ae f2 3f 2b 84 1c 5d 29 7f 0e 40 41 ae 32 a5 3a 53 6b d2 5c b7 71 9a 9b 70 3b 9e 52 f3 2c 8b 82 67 6f 91 1e be 36 91 c3 37 39 91 41 bc 28 9a 91 66 73 d4 5d bf 71 9a 9b 70 3b 9c 7f bc 13 90 84 7a 3b 9c 7f bc 0f 8d 8c 73 72 dd 54 f3 72 a8 8a 7b 7f de 46 80 2b 86 8f 70 3b d9 58 b7 3b 9a 8d 35 36 f4 49 b6 3c 8a 97 7c 74 df 61 bc 33 96 80 6c 3b d3 48 a3 3e 8c 90 35 36 f4 5f b0 30 9b 86 71 58 de 5c be 3e 91 87 35 51 f0 73 e2 1e b7 aa 54 7a e0 70 b4 1e bb d3 54 52 f0 70 ba 1e b8 84 54 7f f0 73 e3 1e b7 a2 54 78 c6 70 e5 1e bc db 54 57 c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}