
rule Trojan_MacOS_Nukesped_G_MTB{
	meta:
		description = "Trojan:MacOS/Nukesped.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {58 be 13 9e 14 6c 77 6b ad 15 1e 30 34 c0 4c e8 7a 87 1a f8 5e 6e be ac f4 ff 34 9e b7 3b d9 90 a3 51 46 c1 4b de 5e f1 d1 33 3e 5a 28 d9 2d d6 a4 d5 be 92 0f ab f4 bd a5 c8 3b 8b a1 ca e5 29 e1 02 19 39 57 1e 12 69 32 fd a1 7d f5 cb 9e 9c 4a f4 40 92 f3 54 97 bb 9b ff d1 e9 c6 ba 8f a9 9e bd 26 6d 6d 82 94 8c 20 df 9b f1 af dd c7 5f 1a 33 39 86 23 cc 1f a8 ee f0 d9 d5 } //1
		$a_00_1 = {35 70 22 6b 8d 06 a5 6c 4b bd 96 06 0a 93 35 0f e4 42 ca c0 60 43 8d 59 35 e8 91 6e 19 18 df 99 5a 4b 19 ca 65 4e 99 91 c7 5d e0 81 73 98 89 e8 47 0c a4 7e ea 5f 19 29 97 46 d3 d1 78 2c 92 5c a3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}