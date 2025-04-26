
rule TrojanDownloader_O97M_Obfuse_PDN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 } //1 =chr(50)+chr(48)+chr(48)
		$a_01_1 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 } //1 specialpath=wshshell.specialfolders("recent")
		$a_01_2 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 61 70 70 64 61 74 61 22 29 } //1 specialpath=wshshell.specialfolders("appdata")
		$a_03_3 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c [0-0a] 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 64 2e 6d 2f 71 6d 7a 6c 62 6b 67 2f 6b 68 62 76 68 2e } //1
		$a_03_4 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c [0-0a] 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 64 2e 6d 2f 67 6a 6b 6b 68 68 68 67 2f 6b 6a 64 68 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}