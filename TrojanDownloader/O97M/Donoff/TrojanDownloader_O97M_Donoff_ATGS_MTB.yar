
rule TrojanDownloader_O97M_Donoff_ATGS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ATGS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 6f 6e 61 73 2e 41 64 61 6d 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 70 71 77 6f 65 69 71 6a 64 61 6d 73 64 61 6a 6b 73 68 64 } //1 Theonas.Adam = "bitly.com/pqwoeiqjdamsdajkshd
		$a_01_1 = {52 65 74 75 72 6e 56 61 6c 75 65 20 3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 28 30 26 2c 20 63 6d 64 6c 69 6e 65 24 2c 20 30 26 2c 20 30 26 2c 20 31 26 2c 20 5f } //1 ReturnValue = CreateProcess(0&, cmdline$, 0&, 0&, 1&, _
		$a_03_2 = {6f 62 6a 2e 20 5f 90 0c 02 00 53 61 62 6f 74 61 67 65 20 5f 90 0c 02 00 28 54 68 65 6f 6e 61 73 2e 4d 69 6b 68 61 73 20 2b 20 54 68 65 6f 6e 61 73 2e 4e 6f 61 68 20 2b 20 54 68 65 6f 6e 61 73 2e 4e 6f 6e 6f 61 20 2b 20 54 68 65 6f 6e 61 73 2e 53 68 6f 6e 61 73 29 } //1
		$a_03_3 = {6f 62 6a 2e 20 5f 90 0c 02 00 53 65 74 4e 6f 6e 65 6e 65 } //1
		$a_03_4 = {6f 62 6a 2e 20 5f 90 0c 02 00 4d 6f 64 5f 41 75 74 6f 43 61 6c 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}