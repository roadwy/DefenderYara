
rule TrojanDownloader_O97M_EncDoc_C_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.C!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 22 32 30 39 2e 31 34 31 2e 34 32 2e 32 33 2f [0-20] 2e 6a 70 67 22 2c 20 46 61 6c 73 65 } //1
		$a_03_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c [0-20] 2e 65 78 65 22 } //1
		$a_01_2 = {53 68 65 6c 6c 41 70 70 2e 4f 70 65 6e } //1 ShellApp.Open
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}