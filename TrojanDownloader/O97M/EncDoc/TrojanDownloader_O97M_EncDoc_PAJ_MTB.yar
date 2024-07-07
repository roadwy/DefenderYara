
rule TrojanDownloader_O97M_EncDoc_PAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 68 78 6b 68 64 5f 5f 62 69 74 73 37 2c 6e 62 32 28 74 75 65 73 64 61 79 34 28 22 2b 77 30 76 69 34 38 35 22 29 2c 22 76 79 67 71 6a 79 22 29 } //1 nhxkhd__bits7,nb2(tuesday4("+w0vi485"),"vygqjy")
		$a_01_1 = {67 65 6e 65 72 61 74 69 6f 6e 73 38 3d 61 70 69 31 26 6e 62 32 28 74 75 65 73 64 61 79 34 28 22 68 71 3d 3d 22 29 2c 22 67 71 76 6f 6d 71 22 29 26 61 73 73 75 6d 70 74 69 6f 6e 31 63 61 6c 6c 62 79 6e 61 6d 65 76 61 32 2c 73 74 72 72 65 76 65 72 73 65 28 63 68 72 28 28 31 31 2b 39 39 29 29 26 63 68 72 28 28 31 31 36 2b 31 29 29 26 63 68 72 28 28 31 31 35 2d 33 33 29 29 29 2c 28 31 2b 30 29 2c 67 65 6e 65 72 61 74 69 6f 6e 73 38 } //1 generations8=api1&nb2(tuesday4("hq=="),"gqvomq")&assumption1callbynameva2,strreverse(chr((11+99))&chr((116+1))&chr((115-33))),(1+0),generations8
		$a_01_2 = {63 61 6c 6c 62 79 6e 61 6d 65 61 6c 67 6f 72 69 74 68 6d 32 2c 73 74 72 72 65 76 65 72 73 65 28 63 68 72 28 31 31 30 29 26 63 68 72 28 31 30 31 29 26 63 68 72 28 31 31 32 29 26 63 68 72 28 37 39 29 29 2c 28 30 2b 31 29 2c 6a 6f 75 72 6e 61 6c 69 73 74 34 2c 2c 74 72 75 65 2c 2c 2c 2c 2c 2c 2c 2c 2c 66 61 6c 73 65 } //1 callbynamealgorithm2,strreverse(chr(110)&chr(101)&chr(112)&chr(79)),(0+1),journalist4,,true,,,,,,,,,false
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}