
rule Trojan_AndroidOS_funkyBot_A{
	meta:
		description = "Trojan:AndroidOS/funkyBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 33 35 66 38 36 63 36 36 37 62 32 37 35 63 61 31 64 33 30 36 36 64 33 66 61 63 34 35 38 37 64 } //2 d35f86c667b275ca1d3066d3fac4587d
		$a_01_1 = {34 33 32 31 30 33 61 35 31 37 35 31 63 66 66 32 61 35 39 31 61 39 61 62 66 39 34 39 39 63 30 66 } //2 432103a51751cff2a591a9abf9499c0f
		$a_01_2 = {4c 6a 61 76 61 2f 75 74 69 6c 2f 7a 69 70 2f 5a 69 70 46 69 6c 65 } //1 Ljava/util/zip/ZipFile
		$a_01_3 = {61 47 56 73 62 47 38 67 64 32 39 79 62 47 51 67 62 58 6b 7a 4d 67 3d 3d } //1 aGVsbG8gd29ybGQgbXkzMg==
		$a_01_4 = {63 73 6e 2d 72 65 73 70 2e 64 61 74 61 } //1 csn-resp.data
		$a_01_5 = {6c 69 62 63 73 6e 32 } //1 libcsn2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}