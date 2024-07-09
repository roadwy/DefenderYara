
rule TrojanDownloader_O97M_Obfuse_JN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 63 6a 74 74 2e 66 72 2f 70 64 66 2f 74 65 73 74 2e 65 78 65 } //1 https://scjtt.fr/pdf/test.exe
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 44 6f 77 6e 6c 6f 61 64 73 5c 62 61 74 74 65 72 79 2e 65 78 65 } //1 C:\Users\" & Environ("UserName") & "\Downloads\battery.exe
		$a_01_2 = {53 68 65 6c 6c 28 44 65 73 74 69 6e 61 74 69 6f 6e 46 69 6c 65 2c 20 31 29 } //1 Shell(DestinationFile, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_JN_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 53 22 20 26 20 22 68 22 20 26 20 22 65 22 20 26 20 22 6c 22 20 26 20 22 6c 22 } //1 = "S" & "h" & "e" & "l" & "l"
		$a_01_1 = {3d 20 22 57 22 20 26 20 22 53 22 20 26 20 22 63 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 70 22 20 26 20 22 74 22 } //1 = "W" & "S" & "c" & "r" & "i" & "p" & "t"
		$a_01_2 = {3d 20 22 20 2d 65 5e 22 20 26 20 22 6e 5e 63 20 22 } //1 = " -e^" & "n^c "
		$a_01_3 = {3d 20 22 20 20 2d 65 6e 63 20 22 } //1 = "  -enc "
		$a_01_4 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 = VBA.CreateObject(
		$a_03_5 = {2e 52 75 6e 28 [0-09] 2c 20 30 2c 20 46 61 6c 73 65 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JN_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 22 } //1 WinHttpReq.Open "GET", myURL, False, "username", "password"
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 31 30 30 2e 35 2f 74 65 73 74 64 61 74 61 2e 74 78 74 } //1 http://192.168.100.5/testdata.txt
		$a_01_2 = {53 61 76 65 54 6f 46 69 6c 65 20 22 43 3a 5c 55 73 65 72 73 5c 45 6e 69 67 6d 61 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 30 32 72 65 76 5c 6d 79 74 65 73 74 2e 74 78 74 22 2c 20 32 20 27 20 31 } //1 SaveToFile "C:\Users\Enigma\source\repos\02rev\mytest.txt", 2 ' 1
		$a_01_3 = {50 6f 77 65 72 53 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 22 7b 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 31 30 30 2e 35 2f 74 65 73 74 64 61 74 61 2e 74 78 74 20 2d 4f 75 74 46 69 6c 65 } //1 PowerShell -Command ""{Invoke-WebRequest -Uri http://192.168.100.5/testdata.txt -OutFile
		$a_01_4 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 4e 65 74 4c 6f 67 67 65 72 2e 65 78 65 } //1 Environ("USERPROFILE") & "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\NetLogger.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}