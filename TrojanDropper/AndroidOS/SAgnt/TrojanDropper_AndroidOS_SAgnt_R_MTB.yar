
rule TrojanDropper_AndroidOS_SAgnt_R_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.R!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {14 c1 04 91 e0 03 14 aa b5 a3 02 d1 ea 69 fe 97 40 01 80 52 e1 03 14 aa 0f 68 fe 97 b8 db 36 a9 b7 e7 35 a9 a1 02 40 ad a0 23 02 d1 e2 03 03 91 e1 03 13 aa e1 03 06 ad 1b 69 fe 97 a0 83 57 f8 fd 68 fe 97 c0 00 00 90 00 80 08 91 e1 03 1f 2a e2 03 1f 2a b4 6b fe 97 a2 83 57 f8 c1 00 00 90 21 50 09 91 40 00 80 52 } //2
		$a_01_1 = {c6 10 63 f7 5d d3 5d ab 6c d4 5d ab 6c 1f 55 0a 4e d7 5d ab 6c 06 10 db 23 ac 92 cb 41 d7 5d ab 6c 30 12 54 b7 f4 88 ab f4 d8 5d ab 6c 7f bc c0 2b d8 5d ab 6c a5 76 c9 48 40 bc 4d 6a dc 0d a6 78 8b 7f 97 9a fd bc 5e ea 4b 26 43 a6 19 f4 03 32 95 1d 22 73 44 d2 7e 2e 47 0b 1a 6c 53 5e 72 dd d5 4e 25 9e 45 bd 19 7b b1 56 11 93 ba 5b 8a b8 3f ce ed ea 4f 8c ee 75 35 76 e9 68 29 ac a6 40 66 23 2a 48 c5 35 f4 e1 1b c5 97 ca 33 bd 8c 66 f9 4c 0c a4 cb 3f 7b 81 17 62 b5 86 14 55 e1 5e df 2d e3 88 45 83 ae 78 14 b0 c6 f9 7d f3 83 9a 11 52 36 36 cd a8 87 f9 bf 3e bb 6f 35 56 cd f4 28 10 d3 7d ef 33 05 b0 f0 33 05 b0 12 89 9b 9d e9 9f b4 76 8e e3 } //2
		$a_01_2 = {a0 64 f5 63 aa 62 73 d7 80 83 97 a3 40 c9 b5 16 2b 3d ee f0 95 47 01 81 f0 c1 43 18 2b 3d ee 4f 91 61 4b 1b 2b 3d ee 1a 2b 3d ee 2b 5e fd 56 73 19 b3 7b fe cd 2a 25 44 32 7a 70 97 8d a9 0f 8d c3 72 dc 21 2b 3d ee 23 2b 3d ee 40 66 02 88 54 74 e2 d4 3b 08 36 c1 6d 23 41 8d 7f 6c 90 b7 28 2b 3d ee 47 b4 33 dc e3 c4 e6 c5 f0 da 10 18 2d 2b 3d ee 2e 2b 3d ee 09 27 eb b2 } //1
		$a_01_3 = {30 00 31 00 33 00 35 00 37 00 6b 00 54 00 44 00 46 00 58 00 57 00 55 00 48 00 4a 00 50 00 3b 00 4b 00 23 00 6a 00 51 00 47 00 } //1 01357kTDFXWUHJP;K#jQG
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}