
rule TrojanDownloader_O97M_Obfuse_SK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //1 'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
		$a_03_1 = {3d 20 52 61 6e 67 65 28 90 02 02 29 2e 43 6f 6d 6d 65 6e 74 2e 54 65 78 74 90 00 } //1
		$a_01_2 = {57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 41 63 74 69 76 61 74 65 } //1 Worksheets(1).Activate
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = CreateObject("winmgmts:Win32_Process")
		$a_03_4 = {2e 4d 65 74 68 6f 64 73 5f 28 22 43 72 65 61 74 65 22 29 2e 20 5f 90 02 10 49 6e 50 61 72 61 6d 65 74 65 72 73 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_SK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 4d 73 67 42 6f 78 } //1 'MsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBoxMsgBox
		$a_01_1 = {22 66 75 63 6b 22 } //1 "fuck"
		$a_01_2 = {22 79 6f 75 22 } //1 "you"
		$a_01_3 = {46 69 65 6c 64 53 74 72 20 3d 20 53 70 6c 69 74 28 54 6d 70 2c 20 22 2f 2f 2f 22 29 } //1 FieldStr = Split(Tmp, "///")
		$a_01_4 = {3d 20 43 68 72 28 22 26 48 22 20 26 20 4d 69 64 28 73 44 61 74 61 2c 20 69 43 68 61 72 2c 20 32 29 29 } //1 = Chr("&H" & Mid(sData, iChar, 2))
		$a_03_5 = {3d 20 6f 50 72 6f 63 65 73 73 2e 45 78 65 63 4d 65 74 68 6f 64 5f 28 73 48 65 78 44 65 63 6f 64 65 28 22 90 02 18 22 29 2c 20 6f 49 6e 50 61 72 61 6d 73 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}