
rule TrojanDownloader_O97M_Obfuse_DO{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DO,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 7a 28 29 } //1 Public Sub z()
		$a_03_1 = {3d 20 53 68 65 6c 6c 28 90 02 10 2c 20 30 29 90 00 } //1
		$a_03_2 = {3d 20 52 6f 75 6e 64 28 90 02 08 2e 90 02 10 29 90 00 } //1
		$a_03_3 = {3d 20 53 67 6e 28 90 02 04 29 90 00 } //1
		$a_01_4 = {43 61 6c 6c 20 7a } //1 Call z
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_DO_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DO,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 7a 28 29 } //1 Public Sub z()
		$a_03_1 = {3d 20 53 68 65 6c 6c 28 90 02 10 2c 20 30 29 90 00 } //1
		$a_03_2 = {53 74 72 52 65 76 65 72 73 65 28 90 02 08 2e 6d 79 6e 65 77 74 78 74 2e 54 65 78 74 29 90 00 } //1
		$a_03_3 = {3d 20 56 61 6c 28 90 02 08 2e 90 02 10 29 90 00 } //1
		$a_01_4 = {43 61 6c 6c 20 7a } //1 Call z
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}