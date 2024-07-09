
rule TrojanDownloader_O97M_Donoff_RBP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RBP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6c 6f 67 69 6e 2e 61 74 74 61 63 68 6d 65 6e 74 2d 74 65 73 74 31 32 2e 73 65 63 75 72 65 6c 79 2d 6c 6f 67 6f 75 74 2e 63 6f 6d 2f 61 70 69 2f 41 6e 61 6c 79 74 69 63 73 2f 4d 61 63 72 6f 3f 69 69 64 3d 66 66 65 31 37 65 33 34 2d 36 37 34 32 2d 34 30 38 30 2d 62 33 37 38 2d 38 34 36 63 63 35 39 65 34 66 35 62 90 0a 6f 00 68 74 74 70 3a 2f 2f } //1
		$a_01_1 = {4d 79 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 5f } //1 MyRequest.Open "GET", _
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 } //1 CreateObject("WinHttp.WinHttpRequest.5.1")
		$a_01_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_4 = {4d 79 52 65 71 75 65 73 74 2e 53 65 6e 64 } //1 MyRequest.Send
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}