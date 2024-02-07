
rule TrojanDownloader_O97M_Obfuse_PBRF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBRF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 22 64 7a 30 6e 68 6c 6a 31 71 38 61 63 33 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 22 6d 65 74 68 6f 64 3d 22 90 03 04 05 68 74 74 70 68 74 74 70 73 22 66 69 6c 65 6e 61 6d 65 3d 22 6d 61 6c 77 61 72 65 2e 65 78 65 22 90 00 } //01 00 
		$a_01_1 = {75 72 6c 3d 6d 65 74 68 6f 64 2b 22 3a 2f 2f 22 2b 68 6f 73 74 2b 22 2f 22 2b 66 69 6c 65 6e 61 6d 65 6c 6f 63 61 6c } //01 00  url=method+"://"+host+"/"+filenamelocal
		$a_01_2 = {66 69 6c 65 70 61 74 68 3d 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 22 2b 66 69 6c 65 6e 61 6d 65 } //00 00  filepath="c:\windows\tasks\"+filename
	condition:
		any of ($a_*)
 
}