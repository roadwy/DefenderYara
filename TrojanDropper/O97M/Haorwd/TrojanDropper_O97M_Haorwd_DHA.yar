
rule TrojanDropper_O97M_Haorwd_DHA{
	meta:
		description = "TrojanDropper:O97M/Haorwd!DHA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 77 69 72 64 2e 65 78 65 22 } //1 Environ("APPDATA") & "\wird.exe"
		$a_00_1 = {45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 6c 6b 6e 22 } //1 Environ("APPDATA") & "\lkn"
		$a_00_2 = {46 69 6c 65 43 6f 70 79 20 6f 57 73 68 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 44 65 73 6b 74 6f 70 22 29 20 26 20 22 5c 22 20 26 20 73 74 72 46 69 6c 65 4e 61 6d 65 2c 20 73 20 26 20 22 5c 22 20 26 20 73 74 72 46 69 6c 65 4e 61 6d 65 } //1 FileCopy oWsh.SpecialFolders("Desktop") & "\" & strFileName, s & "\" & strFileName
		$a_00_3 = {77 65 72 64 2e 65 78 65 } //1 werd.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}