
rule TrojanDownloader_O97M_Powdow_RVAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 4f 62 6a 65 63 74 28 [0-14] 29 2e 47 65 74 28 [0-0f] 29 2e 43 72 65 61 74 65 20 28 22 77 73 63 72 69 70 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-0f] 2e 6a 73 22 29 } //1
		$a_03_1 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d 5c 78 32 30 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f [0-0a] 2e 68 74 6d 2f 66 69 6c 65 27 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}