
rule Trojan_Win32_DcRat_DA_MTB{
	meta:
		description = "Trojan:Win32/DcRat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b1 e3 2c ae cc 59 1c ee e1 0e 9c 8b ab 2d d0 1b db 1c 36 d3 3e 56 ee a6 d5 f1 1f b9 5f fc fd d2 30 92 72 f9 d8 ba 78 } //1
		$a_01_1 = {d1 ef bc 69 e9 e5 b7 99 35 6a b1 18 46 9c 21 0c 96 35 86 5f 90 21 11 f3 } //1
		$a_01_2 = {87 75 59 65 33 7b c5 64 a4 4a 43 a1 95 e3 c8 f7 bc 89 5a de 84 44 57 3a a8 04 ad 06 ce 6e a9 4d 23 bd 15 47 0f 65 5d 96 6f ed 0f 2b fa ff 00 30 6a 76 3d dc bb b1 9f 19 f5 e0 } //1
		$a_01_3 = {69 d4 78 ae 28 f1 af 07 b7 60 f6 2c 3e 85 98 7c 3a b6 ef e7 3a 31 6c 32 a3 bb 1e e8 63 25 a7 6e cf 7a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}