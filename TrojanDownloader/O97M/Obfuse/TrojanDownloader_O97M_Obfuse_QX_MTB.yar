
rule TrojanDownloader_O97M_Obfuse_QX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 22 26 48 22 20 26 20 4d 69 64 28 73 44 61 74 61 2c 20 69 43 68 61 72 2c 20 32 29 29 } //1 = Chr("&H" & Mid(sData, iChar, 2))
		$a_01_1 = {3d 20 22 66 75 63 6b 22 } //1 = "fuck"
		$a_01_2 = {3d 20 22 79 6f 75 22 } //1 = "you"
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 = CreateObject("winmgmts:Win32_ProcessStartup")
		$a_03_4 = {3d 20 6f 50 72 6f 63 65 73 73 2e 4d 65 74 68 6f 64 73 5f 28 73 48 65 78 44 65 63 6f 64 65 28 22 [0-15] 22 29 29 2e 20 5f } //1
		$a_01_5 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 } //1 'MsgBox'MsgBox'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}