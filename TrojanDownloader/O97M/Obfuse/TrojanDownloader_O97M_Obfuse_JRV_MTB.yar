
rule TrojanDownloader_O97M_Obfuse_JRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 28 58 6a 70 6d 20 2b 20 56 79 6d 6e 78 73 73 79 2c 20 54 6a 70 72 7a 2c 20 31 29 } //1 RtlMoveMemory(Xjpm + Vymnxssy, Tjprz, 1)
		$a_01_1 = {72 20 3d 20 53 65 74 50 72 6f 70 41 28 64 2c 20 22 71 64 73 65 22 2c 20 34 35 36 29 } //1 r = SetPropA(d, "qdse", 456)
		$a_01_2 = {50 6f 69 63 7a 79 20 3d 20 41 72 72 61 79 28 32 33 32 2c 20 31 34 33 } //1 Poiczy = Array(232, 143
		$a_01_3 = {58 6a 70 6d 20 3d 20 48 65 61 70 41 6c 6c 6f 63 28 68 2c 20 39 2c 20 55 42 6f 75 6e 64 28 50 6f 69 63 7a 79 29 29 } //1 Xjpm = HeapAlloc(h, 9, UBound(Poiczy))
		$a_01_4 = {48 65 61 70 43 72 65 61 74 65 28 34 30 30 30 31 2c 20 55 42 6f 75 6e 64 28 50 6f 69 63 7a 79 29 2c 20 55 42 6f 75 6e 64 28 50 6f 69 63 7a 79 29 } //1 HeapCreate(40001, UBound(Poiczy), UBound(Poiczy)
		$a_01_5 = {6e 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 } //1 n = ActiveDocument.Name
		$a_01_6 = {49 66 20 4c 65 6e 28 6e 29 20 3c 20 32 35 20 54 68 65 6e } //1 If Len(n) < 25 Then
		$a_01_7 = {53 75 62 20 41 55 74 4f 43 4c 6f 53 65 28 29 } //1 Sub AUtOCLoSe()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}