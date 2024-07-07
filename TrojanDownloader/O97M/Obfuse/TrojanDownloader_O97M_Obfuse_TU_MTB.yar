
rule TrojanDownloader_O97M_Obfuse_TU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.TU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1  = CreateObject("WSCript.shell")
		$a_03_1 = {62 69 67 6d 69 72 2e 68 6f 73 74 2f 90 02 30 2e 65 78 65 22 90 0a 4e 00 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 90 00 } //1
		$a_03_2 = {57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f 90 02 20 2e 65 78 65 22 90 0a 32 00 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 2f 2f 90 00 } //1
		$a_03_3 = {57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 90 02 20 2e 65 78 65 22 90 0a 2c 00 2e 52 75 6e 20 22 22 22 43 3a 5c 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}