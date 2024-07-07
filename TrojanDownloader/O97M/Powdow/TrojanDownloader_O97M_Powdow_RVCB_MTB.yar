
rule TrojanDownloader_O97M_Powdow_RVCB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 73 68 65 6c 6c 2e 72 75 6e 22 63 6d 64 2f 63 22 26 73 61 76 65 70 61 74 68 26 22 3e 6e 75 6c 32 3e 26 31 22 2c 30 2c 74 72 75 65 65 6e 64 73 75 62 } //1 =createobject("wscript.shell")shell.run"cmd/c"&savepath&">nul2>&1",0,trueendsub
		$a_01_1 = {75 72 6c 3d 22 68 74 74 70 73 3a 2f 2f 6c 6c 6f 79 64 66 65 64 64 65 72 2e 63 6f 6d 2f 73 69 32 6f 72 2e 62 61 74 22 27 64 6f 77 6e 6c 6f 61 64 74 68 65 66 69 6c 65 } //1 url="https://lloydfedder.com/si2or.bat"'downloadthefile
		$a_01_2 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {78 78 78 78 78 78 5f 2e 5f 6c 6f 61 64 28 22 68 74 74 70 90 02 64 2e 74 78 74 22 29 78 78 78 78 78 78 5f 2e 5f 74 72 61 6e 73 66 6f 72 6d 6e 6f 64 65 78 78 78 78 78 78 65 6e 64 73 75 62 90 00 } //1
		$a_01_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 32 39 33 33 62 66 39 30 2d 37 62 33 36 2d 31 31 64 32 2d 62 32 30 65 2d 30 30 63 30 34 66 39 38 33 65 36 30 7d 22 29 3a 3a 3a 3a 3a 3a 3a 3a 3a 78 78 78 78 78 78 5f 2e 5f 61 73 79 6e 63 3d 66 61 6c 73 65 3a 3a } //1 createobject("new:{2933bf90-7b36-11d2-b20e-00c04f983e60}"):::::::::xxxxxx_._async=false::
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //1 workbook_open()::
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}