
rule TrojanDownloader_O97M_Donoff_AH{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AH,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 72 6f 6d 41 72 72 28 29 20 41 73 20 56 61 72 69 61 6e 74 2c 20 4c 65 6e 4c 65 6e 20 41 73 20 49 6e 74 65 67 65 72 } //1 fromArr() As Variant, LenLen As Integer
		$a_01_1 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 4c 65 6e 4c 65 6e 20 2b 20 69 20 2a 20 32 29 } //1 result = result & Chr(fromArr(i) - LenLen + i * 2)
		$a_01_2 = {41 72 72 61 79 28 31 34 36 2c 20 31 35 36 2c 20 31 35 34 2c 20 31 34 38 2c 20 39 32 2c 20 37 39 } //1 Array(146, 156, 154, 148, 92, 79
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 22 20 2b 20 66 69 67 61 72 6f 20 2b 20 22 54 22 2c 20 48 6c 6f 70 75 73 68 6b 61 2c 20 46 61 6c 73 65 } //1 .Open "GE" + figaro + "T", Hlopushka, False
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}