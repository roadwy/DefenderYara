
rule Ransom_Win64_GoFrnds_YAR_MTB{
	meta:
		description = "Ransom:Win64/GoFrnds.YAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 8b 4c 24 4c 41 8d b1 65 78 70 61 33 70 20 c1 c6 10 8b 7c 24 3c 01 f7 89 7c 24 70 44 31 cf c1 c7 0c 45 8d 14 39 46 8d 0c 0f 45 8d 89 65 78 70 61 41 31 f1 } //10
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //10 Go build ID:
		$a_01_2 = {33 2d 50 38 48 58 64 50 35 6c 57 65 73 4c 65 69 74 68 67 58 2f 56 69 53 45 65 6a 6b 57 37 62 6e 30 38 65 45 37 4c 6a 6b 63 2f 66 64 5f 43 4b 38 66 43 5f 52 78 30 4b 55 56 67 55 45 34 75 2f 38 38 41 78 36 56 67 2d 79 73 39 30 64 4b 56 35 71 6d 59 5f } //1 3-P8HXdP5lWesLeithgX/ViSEejkW7bn08eE7Ljkc/fd_CK8fC_Rx0KUVgUE4u/88Ax6Vg-ys90dKV5qmY_
		$a_01_3 = {2e 66 72 6e 64 73 } //10 .frnds
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10) >=31
 
}