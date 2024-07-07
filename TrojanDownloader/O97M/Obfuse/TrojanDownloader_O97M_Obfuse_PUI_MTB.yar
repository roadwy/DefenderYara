
rule TrojanDownloader_O97M_Obfuse_PUI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PUI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {54 65 6d 70 50 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c 22 } //1 TempPath = Environ("TMP") + "\"
		$a_00_1 = {5c 61 70 70 64 61 74 61 5c 72 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 42 61 63 6b 75 70 2e 76 62 73 } //1 \appdata\roaming\MicrosoftBackup.vbs
		$a_00_2 = {4d 5a 25 39 30 25 30 30 25 30 33 25 30 30 } //1 MZ%90%00%03%00
		$a_00_3 = {3d 20 22 22 20 2f 73 20 22 22 20 2b 20 61 70 70 70 61 74 68 20 2b 20 22 22 5c 62 61 63 6b 75 70 2e 64 6c 6c 22 22 22 20 26 20 76 62 4e 65 77 4c 69 6e 65 } //1 = "" /s "" + apppath + ""\backup.dll""" & vbNewLine
		$a_00_4 = {6f 57 53 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 73 74 61 72 74 75 70 22 22 29 22 20 26 20 76 62 4e 65 77 4c 69 6e 65 } //1 oWS.SpecialFolders(""startup"")" & vbNewLine
		$a_00_5 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 2c 20 22 22 2c 20 22 22 } //1 WinHttpReq.Open "POST", myURL, False, "", ""
		$a_00_6 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 22 20 2b 20 4f 75 74 50 75 74 46 69 6c 65 4e 61 6d 65 2c 20 76 62 48 69 64 65 } //1 Shell "wscript " + OutPutFileName, vbHide
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}