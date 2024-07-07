
rule TrojanDownloader_O97M_Donoff_AL{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AL,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 72 6f 6d 41 72 72 28 29 20 41 73 20 56 61 72 69 61 6e 74 2c 20 4c 65 6e 4c 65 6e 20 41 73 20 49 6e 74 65 67 65 72 } //1 fromArr() As Variant, LenLen As Integer
		$a_01_1 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 32 20 2a 20 4c 65 6e 4c 65 6e 20 2d 20 69 20 2a } //1 result = result & Chr(fromArr(i) - 2 * LenLen - i *
		$a_01_2 = {50 75 73 68 5f 45 20 2b 20 50 75 73 68 5f 4d 20 2b 20 50 75 73 68 5f 50 } //1 Push_E + Push_M + Push_P
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 } //1 .Open "GET", GetStringFromArray(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}