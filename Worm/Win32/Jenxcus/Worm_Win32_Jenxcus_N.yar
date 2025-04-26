
rule Worm_Win32_Jenxcus_N{
	meta:
		description = "Worm:Win32/Jenxcus.N,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {ec 5b 8d 7c de bb 85 14 e3 13 d8 53 d3 92 70 c8 41 55 33 21 45 41 30 36 0c ff ec 9e c6 3d 06 3d 1d a8 0f 33 c0 db 7d 6f 6b 43 ca 52 af ad 00 00 } //4
		$a_01_1 = {29 58 e3 b5 f7 e8 30 dc a8 11 3d 1d e7 9a b5 fc a7 08 27 17 34 bc 23 0c 57 3e 61 1a 12 c7 49 43 } //1
		$a_01_2 = {10 cd 67 4d 8e 8b 41 9c fc 20 90 f9 6f b1 be 13 2f ac cb d1 4a 9c 85 9c ee 27 04 56 3a 59 7a 83 } //1
		$a_01_3 = {df d5 e9 72 07 b0 7b ae 8c 2e 01 8f c5 d8 ee a6 a2 ba f9 95 34 60 65 39 69 ee e1 e1 eb d9 fe 2b } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}