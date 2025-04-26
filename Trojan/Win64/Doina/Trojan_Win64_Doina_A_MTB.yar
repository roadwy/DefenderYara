
rule Trojan_Win64_Doina_A_MTB{
	meta:
		description = "Trojan:Win64/Doina.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {15 82 95 d2 02 74 24 58 8b c3 aa 19 4f f5 26 b5 19 a0 0f f1 0d 6e 9d f3 0d c8 15 f0 0d c9 f0 0d ca b0 0b cb 55 c6 54 40 cc b0 0a cd 70 0e ce 70 0c cf 55 70 0e d0 30 09 d1 b0 0c d2 f0 09 d3 55 30 01 d4 70 0e d5 b0 02 d6 b0 00 d7 55 70 01 d8 30 00 d9 30 02 da 70 0b db 55 b0 03 dc 70 0e dd b0 00 de f0 02 df 55 } //1
		$a_01_1 = {40 9c 55 00 e5 9d c0 02 9e 80 76 9f 80 72 a0 05 60 02 a1 00 6f a2 6f c6 40 a3 00 67 c6 40 a4 49 c6 40 a5 00 6e c6 40 a6 64 c6 40 a7 15 e0 03 a8 60 07 a9 e0 05 aa 63 c6 04 40 ab 60 07 ac 50 c6 40 ad 15 60 06 ae e0 02 af e0 00 b0 6d c6 00 40 b1 57 44 88 60 b2 c6 00 40 88 75 c6 40 89 73 c6 54 40 8a e0 05 8b e0 03 8c 80 79 8d 00 32 c6 40 8e 2e c6 40 8f 25 e0 09 90 e0 0c 91 6c 60 05 92 ff 88 15 11 41 61 65 54 24 40 a2 5f 0a 1b a0 01 41 c0 62 64 44 89 a4 04 24 b8 e0 17 48 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}