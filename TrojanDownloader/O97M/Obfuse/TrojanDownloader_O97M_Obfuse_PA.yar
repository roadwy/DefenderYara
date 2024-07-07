
rule TrojanDownloader_O97M_Obfuse_PA{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 72 72 61 79 28 90 02 10 2c 20 90 02 10 2c 20 90 02 10 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 90 02 10 28 90 02 10 2e 54 65 78 74 42 6f 78 31 29 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Obfuse_PA_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_00_1 = {53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 } //1 Sub AutoClose()
		$a_00_2 = {56 61 6c 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 4d 61 69 6c 53 79 73 74 65 6d 29 20 4c 69 6b 65 20 56 61 6c 28 31 29 } //2 Val(Application.MailSystem) Like Val(1)
		$a_02_3 = {53 65 74 20 90 02 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 20 29 90 00 } //2
		$a_02_4 = {2e 52 75 6e 20 90 02 10 2c 20 90 00 } //2
		$a_02_5 = {24 70 61 74 68 90 02 01 27 3b 24 90 02 10 22 90 00 } //2
		$a_02_6 = {20 2d 53 63 6f 70 65 90 02 20 22 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2+(#a_02_5  & 1)*2+(#a_02_6  & 1)*2) >=11
 
}