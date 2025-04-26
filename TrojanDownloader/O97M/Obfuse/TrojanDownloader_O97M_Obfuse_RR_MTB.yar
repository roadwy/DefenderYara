
rule TrojanDownloader_O97M_Obfuse_RR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 29 20 2d 20 73 65 63 6f 6e 64 29 } //1 Mid(strInput, first, 1) = Chr(Asc(Mid(strInput, first, 1)) - second)
		$a_03_1 = {25 39 39 39 25 39 39 39 40 6a 2e 6d 70 2f 61 73 64 6e 77 77 6f 64 70 77 70 6b 6b 6b 22 90 0a 2f 00 68 74 74 70 3a 2f 2f } //1
		$a_01_2 = {64 65 63 72 79 70 74 28 22 70 22 2c 20 22 33 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 7c 22 2c 20 22 39 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 6f 22 2c 20 22 37 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 7d 22 2c 20 22 39 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 63 22 2c 20 22 32 22 29 } //1 decrypt("p", "3") + decrypt("|", "9") + decrypt("o", "7") + decrypt("}", "9") + decrypt("c", "2")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}