
rule TrojanDownloader_O97M_Powdow_PW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //1 powershell.exe -WindowStyle Hidden
		$a_02_1 = {63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f 7a 2f [0-06] 2e 6a 70 67 90 0a 32 00 68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e } //1
		$a_00_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1 Start-Process -FilePath
		$a_02_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-0a] 2e 65 78 65 } //1
		$a_00_4 = {77 69 6e 6d 67 6d 74 73 3a 77 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //1 winmgmts:win32_Process
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_PW_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 79 66 75 6e 63 31 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 63 61 64 29 } //1 myfunc1 = StrReverse(cad)
		$a_01_1 = {28 67 6e 69 72 74 73 64 61 6f 6c 6e 77 6f 64 2e 29 74 6e 65 69 6c 63 62 65 77 2e 74 65 6e 2e 6d 65 74 73 79 73 20 74 63 65 6a 62 6f 2d 77 65 6e 28 28 78 65 69 20 63 2d 20 70 6f 6e 2d 20 73 73 61 70 79 62 20 63 65 78 65 2d 20 6c 6c 65 68 73 72 65 77 6f 70 22 29 } //1 (gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")
		$a_01_2 = {2e 47 65 74 28 6d 79 66 75 6e 63 31 28 22 73 73 65 63 6f 72 50 5f 32 33 6e 69 57 22 29 29 2e 43 72 65 61 74 65 20 73 74 72 41 72 67 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 69 64 } //1 .Get(myfunc1("ssecorP_23niW")).Create strArg, Null, Null, pid
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}