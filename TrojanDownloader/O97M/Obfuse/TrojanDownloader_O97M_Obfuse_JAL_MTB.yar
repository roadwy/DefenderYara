
rule TrojanDownloader_O97M_Obfuse_JAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 37 39 2e 31 34 31 2e 31 36 35 2e 31 37 33 2f 44 58 2f 46 44 2d 90 02 06 2e 6a 70 67 90 00 } //2
		$a_03_1 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 90 02 0f 2e 65 78 65 90 00 } //2
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 } //1 powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass  -command
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}