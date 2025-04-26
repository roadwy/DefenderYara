
rule TrojanDownloader_Win32_Psloader_B{
	meta:
		description = "TrojanDownloader:Win32/Psloader.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 70 00 70 00 47 00 65 00 74 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 6a 00 70 00 67 00 } //1 AppGetLoader.jpg
		$a_03_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 31 39 32 2e 39 39 2e 31 37 35 2e 31 32 33 [0-20] 2e 7a 69 70 27 2c 27 43 3a 5c 48 41 4c 39 54 48 [0-20] 2e 7a 69 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}