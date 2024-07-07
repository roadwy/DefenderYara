
rule TrojanDownloader_Linux_Equipdo_B{
	meta:
		description = "TrojanDownloader:Linux/Equipdo.B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 22 68 74 74 70 3a } //1 Call DownloadFile("http:
		$a_00_1 = {2f 62 69 68 2f 73 73 2e 65 78 65 22 2c 20 22 65 33 65 33 65 33 2e 65 78 65 } //1 /bih/ss.exe", "e3e3e3.exe
		$a_01_2 = {4d 73 67 42 6f 78 20 22 45 73 74 65 20 64 6f 63 75 6d 65 6e 74 6f 20 6e 6f 20 65 73 20 63 6f 6d 70 61 74 69 62 6c 65 20 63 6f 6e 20 65 73 74 65 } //1 MsgBox "Este documento no es compatible con este
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Linux_Equipdo_B_2{
	meta:
		description = "TrojanDownloader:Linux/Equipdo.B,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 4d 4c 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 4f 50 45 52 41 28 22 58 58 58 22 29 2c 20 46 61 6c 73 65 } //1 XML.Open "GET", OPERA("XXX"), False
		$a_01_1 = {46 75 6c 6c 53 61 76 65 50 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 53 61 76 65 50 61 74 68 29 20 26 20 22 5c 22 20 26 20 4f 50 45 52 41 28 22 4a 4b 48 44 4b 53 41 44 53 22 29 } //1 FullSavePath = Environ(SavePath) & "\" & OPERA("JKHDKSADS")
		$a_01_2 = {4d 73 67 42 6f 78 20 22 45 73 74 65 20 64 6f 63 75 6d 65 6e 74 6f 20 6e 6f 20 65 73 20 63 6f 6d 70 61 74 69 62 6c 65 20 63 6f 6e 20 65 73 74 65 20 65 71 75 69 70 6f 2e 22 20 26 20 76 62 43 72 4c 66 } //1 MsgBox "Este documento no es compatible con este equipo." & vbCrLf
		$a_01_3 = {22 63 69 64 22 20 3d 20 22 63 69 64 22 20 54 68 65 6e 3a 20 4f 50 45 52 41 20 3d 20 22 68 74 } //1 "cid" = "cid" Then: OPERA = "ht
		$a_01_4 = {2e 22 20 26 20 22 65 78 22 20 26 20 22 65 22 } //1 ." & "ex" & "e"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}