
rule Trojan_O97M_EncDoc_R_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 20 3d 20 48 65 61 70 43 72 65 61 74 65 28 34 30 30 30 31 2c 20 55 42 6f 75 6e 64 28 90 02 0a 29 2c 20 55 42 6f 75 6e 64 28 90 1b 00 29 29 90 00 } //1
		$a_01_1 = {58 6a 70 6d 20 3d 20 48 65 61 70 41 6c 6c 6f 63 28 68 2c 20 39 2c 20 55 42 6f 75 6e 64 28 50 6f 69 63 7a 79 29 29 } //1 Xjpm = HeapAlloc(h, 9, UBound(Poiczy))
		$a_01_2 = {43 74 62 6c 20 3d 20 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 28 58 6a 70 6d 20 2b 20 56 79 6d 6e 78 73 73 79 2c 20 54 6a 70 72 7a 2c 20 31 29 } //1 Ctbl = RtlMoveMemory(Xjpm + Vymnxssy, Tjprz, 1)
		$a_01_3 = {53 75 62 20 41 55 74 4f 5f 43 4c 6f 53 65 28 29 } //1 Sub AUtO_CLoSe()
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}