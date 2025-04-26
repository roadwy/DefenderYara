
rule TrojanDownloader_O97M_Obfuse_PHCC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PHCC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 20 2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 72 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 31 38 2e 31 39 35 2e 31 34 33 2e 31 38 33 2f 37 2f 37 2f ?? ?? ?? 5f [0-14] 2e 65 60 78 65 22 } //1
		$a_03_1 = {26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0f] 2e 65 60 78 65 22 } //1
		$a_01_2 = {6f 62 68 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 } //1 obh = CreateObject(sheee & "l.application").Open(
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}