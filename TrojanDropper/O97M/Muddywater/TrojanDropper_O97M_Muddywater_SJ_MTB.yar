
rule TrojanDropper_O97M_Muddywater_SJ_MTB{
	meta:
		description = "TrojanDropper:O97M/Muddywater.SJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 46 61 69 6c 65 64 20 74 6f 20 73 74 61 72 74 20 70 72 6f 63 65 73 73 2e 20 45 72 72 6f 72 3a 20 22 20 26 20 45 72 72 2e 4c 61 73 74 44 6c 6c 45 72 72 6f 72 } //1 MsgBox "Failed to start process. Error: " & Err.LastDllError
		$a_01_1 = {68 73 74 72 69 6e 67 20 3d 20 52 65 70 6c 61 63 65 28 68 73 74 72 69 6e 67 2c 20 22 3a 22 2c 20 22 22 29 } //1 hstring = Replace(hstring, ":", "")
		$a_01_2 = {72 65 73 75 6c 74 28 69 29 20 3d 20 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 28 68 73 74 72 69 6e 67 2c 20 69 20 2a 20 32 20 2b 20 31 2c 20 32 29 29 } //1 result(i) = Val("&H" & Mid(hstring, i * 2 + 1, 2))
		$a_01_3 = {70 61 74 68 66 69 6c 65 20 3d 20 75 73 65 72 50 72 6f 66 69 6c 65 20 26 20 22 5c 44 6f 77 6e 6c 6f 61 64 73 5c 70 69 63 2e 4c 4f 47 } //1 pathfile = userProfile & "\Downloads\pic.LOG
		$a_03_4 = {62 79 74 65 73 61 70 70 20 3d 20 44 65 63 68 65 78 28 55 73 65 72 46 6f 72 6d 31 2e [0-07] 2e 54 65 78 74 29 } //1
		$a_01_5 = {72 65 74 20 3d 20 43 72 65 61 74 65 41 44 69 72 65 63 74 28 70 61 74 68 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 30 2c 20 30 2c 20 30 2c 20 43 52 45 41 54 45 5f 4e 4f 5f 57 49 4e 44 4f 57 2c 20 30 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 74 73 69 2c 20 74 70 69 29 } //1 ret = CreateADirect(path, vbNullString, 0, 0, 0, CREATE_NO_WINDOW, 0, vbNullString, tsi, tpi)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}