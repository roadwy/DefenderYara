
rule TrojanDownloader_O97M_Obfuse_QRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 65 78 65 63 75 74 65 20 5f 0d 0a 63 61 6c 63 63 63 2c 20 46 } //1
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 45 39 34 41 2d 45 43 31 31 2d 39 37 32 43 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29 29 } //1 GetObject(StrReverse("000045355444-E94A-EC11-972C-02690731:wen"))
		$a_01_2 = {63 61 6c 63 63 63 20 5f 0d 0a 3d 20 5f 0d 0a 58 20 5f 0d 0a 2b 20 5f 0d 0a 59 20 5f } //1
		$a_03_3 = {54 20 5f 0d 0a 3d 20 5f 0d 0a 22 61 90 02 1e 22 0d 0a 45 6e 64 20 5f 90 00 } //1
		$a_01_4 = {4b 20 5f 0d 0a 3d 20 5f 0d 0a 22 6a 2e 6d 70 2f 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}