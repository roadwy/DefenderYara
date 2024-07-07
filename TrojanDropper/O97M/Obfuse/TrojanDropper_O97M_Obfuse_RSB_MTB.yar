
rule TrojanDropper_O97M_Obfuse_RSB_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RSB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 74 65 6d 70 2e 65 78 65 22 } //1 Environ("TMP") & "\temp.exe"
		$a_01_1 = {53 68 65 6c 6c 28 46 4e 61 6d 65 20 2b 20 22 20 31 32 37 2e 30 2e 30 2e 31 20 34 34 34 34 20 2d 65 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 22 2c 20 30 29 } //1 Shell(FName + " 127.0.0.1 4444 -e C:\Windows\System32\cmd.exe", 0)
		$a_01_2 = {50 75 74 20 23 66 6e 75 6d 2c 20 2c 20 48 65 78 44 65 63 6f 64 65 28 43 53 74 72 28 76 76 29 29 } //1 Put #fnum, , HexDecode(CStr(vv))
		$a_01_3 = {43 68 72 28 22 26 48 22 20 26 20 4d 69 64 28 73 44 61 74 61 2c 20 69 43 68 61 72 2c 20 32 29 29 } //1 Chr("&H" & Mid(sData, iChar, 2))
		$a_01_4 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Sub Workbook_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}