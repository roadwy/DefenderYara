
rule TrojanDownloader_O97M_Obfuse_AD{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AD,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4f 70 65 6e 20 72 6f 6d 70 20 2b 20 22 5c 67 72 6f 6f 76 65 31 2e 62 61 74 22 } //1 Open romp + "\groove1.bat"
		$a_00_1 = {3d 20 22 6c 6c 6b 6a 4a 48 67 68 68 68 63 6a 5e 5e 5e 38 38 33 34 6a 68 6a 48 47 47 31 32 34 34 68 5f 5f 2b 2b 22 } //1 = "llkjJHghhhcj^^^8834jhjHGG1244h__++"
		$a_01_2 = {3d 20 22 48 6f 6e 64 61 44 61 22 } //1 = "HondaDa"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}