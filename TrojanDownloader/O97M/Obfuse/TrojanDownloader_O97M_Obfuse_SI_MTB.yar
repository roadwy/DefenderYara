
rule TrojanDownloader_O97M_Obfuse_SI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //1 'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
		$a_01_1 = {2e 45 78 65 63 20 28 53 74 72 52 65 76 65 72 73 65 28 53 74 72 29 29 } //1 .Exec (StrReverse(Str))
		$a_01_2 = {57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 41 63 74 69 76 61 74 65 } //1 Worksheets(1).Activate
		$a_03_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 52 61 6e 67 65 28 22 [0-02] 22 29 2e 43 6f 6d 6d 65 6e 74 2e 54 65 78 74 29 } //1
		$a_03_4 = {3d 20 4a 6f 69 6e 28 [0-02] 2c 20 22 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_SI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-05] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 20 32 33 72 76 73 67 65 72 22 } //1
		$a_01_1 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 } //1 Alias "URLDownloadToFileA" (
		$a_01_2 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 } //1 Public Declare Function URLDownloadToFile Lib "urlmon"
		$a_01_3 = {23 49 66 20 56 42 41 37 20 41 6e 64 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If VBA7 And Win64 Then
		$a_01_4 = {3d 20 22 68 3d 3d 3d 3d 74 3d 3d 3d 3d 74 3d 3d 3d 3d 70 3d 3d 3d 3d 3a 3d 3d 3d 3d 2f 3d 3d 3d 3d 2f 3d 22 } //1 = "h====t====t====p====:====/====/="
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}