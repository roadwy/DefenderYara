
rule TrojanDownloader_O97M_Powdow_RVBO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 3a 2f 2f 36 37 2e 32 31 30 2e 31 31 34 2e 39 39 2f 61 2e 65 78 65 22 66 69 6c 65 70 61 74 68 3d 63 73 74 72 28 65 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 } //1 ttp://67.210.114.99/a.exe"filepath=cstr(environ("appdata")
		$a_01_1 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 28 30 2c 75 72 6c 2c 66 69 6c 65 70 61 74 68 2c 30 2c 30 29 69 66 72 65 73 75 6c 74 3d 30 74 68 65 6e 73 68 65 6c 6c 22 73 68 75 74 64 6f 77 6e 2d 72 2d 74 30 32 22 } //1 urldownloadtofile(0,url,filepath,0,0)ifresult=0thenshell"shutdown-r-t02"
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 workbook_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}