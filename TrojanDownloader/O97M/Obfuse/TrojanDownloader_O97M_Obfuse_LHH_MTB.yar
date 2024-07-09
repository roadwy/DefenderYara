
rule TrojanDownloader_O97M_Obfuse_LHH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LHH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //1 #If VBA7 Then
		$a_01_1 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 65 74 50 69 78 65 6c 20 4c 69 62 20 22 67 64 69 33 32 22 20 28 42 79 56 61 6c 20 68 44 43 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 58 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 59 20 41 73 20 4c 6f 6e 67 50 74 72 2c } //1 Public Declare PtrSafe Function SetPixel Lib "gdi32" (ByVal hDC As LongPtr, ByVal X As LongPtr, ByVal Y As LongPtr,
		$a_03_2 = {48 20 3d 20 48 20 2b 20 [0-20] 20 2a 20 43 6f 73 28 [0-04] 2e [0-15] 20 2b 20 [0-08] 2e [0-15] 20 2a 20 6a 29 } //1
		$a_03_3 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 [0-15] 2e [0-15] 2e 43 61 70 74 69 6f 6e 29 } //1
		$a_03_4 = {27 45 78 65 63 43 6d 64 20 22 43 3a [0-30] 2e 65 78 65 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}