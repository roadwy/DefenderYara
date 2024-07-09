
rule TrojanDownloader_O97M_Obfuse_RX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 22 68 74 74 70 73 3a 2f 2f 72 6f 63 6b 74 72 61 64 65 2e 61 6c 70 68 61 63 6f 64 65 2e 6d 6f 62 69 2f 75 70 6c 6f 61 64 73 2f 62 69 6e 5f 50 72 6f 74 65 63 74 65 64 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1 .Open "get", "https://rocktrade.alphacode.mobi/uploads/bin_Protected.exe", False
		$a_01_1 = {2b 20 22 49 47 5a 4b 47 42 49 2e 65 78 65 22 } //1 + "IGZKGBI.exe"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 48 45 4c 4c 2e 41 50 50 4c 49 43 41 54 49 4f 4e 22 29 } //1 = CreateObject("SHELL.APPLICATION")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_RX_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 28 43 4c 6e 67 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 [0-18] 22 29 2e 56 61 6c 75 65 20 26 20 52 69 67 68 74 28 4c 65 66 74 28 [0-15] 2c 20 [0-15] 29 2c 20 32 29 29 20 2d 20 [0-02] 29 } //1
		$a_03_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 [0-18] 22 29 2e 56 61 6c 75 65 } //1
		$a_01_2 = {53 68 65 6c 6c 20 } //1 Shell 
		$a_01_3 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_RX_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {79 73 74 65 6d 2e 4e 65 74 } //1 ystem.Net
		$a_00_1 = {2e 57 65 62 43 6c 69 65 6e 74 29 22 } //1 .WebClient)"
		$a_00_2 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 22 } //1 .DownloadFi"
		$a_03_3 = {77 65 62 63 65 6e 74 65 72 62 72 61 73 69 6c 2e 63 6f 6d 2e 62 72 2f 73 65 6f 2f 76 68 66 32 2e 90 0a 27 00 68 74 74 70 3a 2f 2f } //1
		$a_00_4 = {50 22 20 2b 20 22 75 22 20 2b 20 22 62 22 20 2b 20 22 6c 22 20 2b 20 22 69 22 20 2b 20 22 63 25 5c 4d 69 63 72 6f 73 6f 66 74 2e 65 } //1 P" + "u" + "b" + "l" + "i" + "c%\Microsoft.e
		$a_00_5 = {78 65 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 22 } //1 xe');Start-Proce"
		$a_00_6 = {22 73 73 20 27 25 50 22 20 2b 20 22 75 22 20 2b 20 22 62 22 20 2b 20 22 6c 22 20 2b 20 22 69 22 20 2b 20 22 63 22 20 2b 20 22 25 5c 4d 22 20 2b 20 22 69 22 20 2b 20 22 63 22 20 2b 20 22 72 22 20 2b 20 22 6f 22 20 2b 20 22 73 22 20 2b 20 22 6f 22 20 2b 20 22 66 22 20 2b 20 22 74 22 20 2b 20 22 2e 65 } //1 "ss '%P" + "u" + "b" + "l" + "i" + "c" + "%\M" + "i" + "c" + "r" + "o" + "s" + "o" + "f" + "t" + ".e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}