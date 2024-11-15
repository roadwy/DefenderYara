
rule TrojanDownloader_O97M_Powdow_RVCK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2d 65 24 63 3b 22 70 72 6f 67 72 61 6d 3d 73 68 65 6c 6c 28 63 6d 64 73 74 72 2c 76 62 68 69 64 65 29 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 3d 74 72 75 65 65 6e 64 73 75 62 } //1 powershell-e$c;"program=shell(cmdstr,vbhide)application.screenupdating=trueendsub
		$a_01_1 = {61 75 74 6f 6f 70 65 6e 28 29 } //1 autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}