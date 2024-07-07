
rule TrojanDownloader_O97M_Obfuse_RZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 28 43 49 6e 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 90 02 18 22 29 2e 56 61 6c 75 65 20 26 20 90 02 18 29 20 2d 20 90 02 02 29 90 00 } //1
		$a_03_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 90 02 18 22 29 2e 56 61 6c 75 65 90 00 } //1
		$a_01_2 = {53 68 65 6c 6c 20 } //1 Shell 
		$a_01_3 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_RZ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 36 38 33 71 31 78 73 68 31 2e 6a 70 67 22 90 0a 34 00 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 90 00 } //1
		$a_00_1 = {45 6e 76 69 72 6f 6e 28 22 41 70 70 44 41 54 41 22 29 } //1 Environ("AppDATA")
		$a_03_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 90 02 05 20 26 20 22 5c 61 76 67 2e 76 62 65 22 90 00 } //1
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_00_4 = {2e 52 75 6e 20 22 61 76 67 2e 76 62 65 } //1 .Run "avg.vbe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}