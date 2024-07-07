
rule TrojanDropper_O97M_Obfuse_BK_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 61 33 66 52 34 74 20 26 20 22 20 22 20 26 20 61 76 63 36 53 67 } //1 Shell a3fR4t & " " & avc6Sg
		$a_01_1 = {3d 20 53 70 6c 69 74 28 61 73 75 4d 57 52 2c 20 43 68 72 28 31 31 20 2b 20 31 31 20 2b 20 31 31 20 2b 20 31 31 29 29 } //1 = Split(asuMWR, Chr(11 + 11 + 11 + 11))
		$a_01_2 = {3d 20 61 4b 66 59 44 51 28 61 50 35 65 57 28 61 79 33 35 6f 28 61 6c 48 56 30 37 29 2c 20 31 35 29 29 } //1 = aKfYDQ(aP5eW(ay35o(alHV07), 15))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDropper_O97M_Obfuse_BK_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 68 68 68 65 61 64 65 72 2e 77 70 66 22 } //1 Open "c:\ProgramData\hhheader.wpf"
		$a_01_1 = {55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 20 3d 20 22 63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 68 68 68 65 61 64 65 72 2e 77 70 66 22 } //1 UserForm1.Label1.Caption = "c:\ProgramData\hhheader.wpf"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 22 20 26 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 32 2e 43 61 70 74 69 6f 6e 20 26 20 22 2e 22 20 26 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 33 2e 43 61 70 74 69 6f 6e 29 } //1 = CreateObject("w" & CommandButton2.Caption & "." & CommandButton3.Caption)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDropper_O97M_Obfuse_BK_MTB_3{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 20 2f 57 20 68 69 64 64 65 6e 20 2f 43 20 24 54 65 6d 70 44 69 72 20 3d 20 5b 45 6e 76 69 72 6f 6e 6d 65 6e 74 5d 3a 3a 47 65 74 46 6f 6c 64 65 72 50 61 74 68 28 27 41 70 70 6c 69 63 61 74 69 6f 6e 44 61 74 61 27 29 } //1 & " /W hidden /C $TempDir = [Environment]::GetFolderPath('ApplicationData')
		$a_01_1 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 (New-Object System.Net.WebClient).DownloadFile
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 61 72 74 61 6e 6f 47 75 69 6d 61 2f 6f 6e 65 6d 6f 72 65 2f 64 6f 77 6e 6c 6f 61 64 73 2f 70 61 79 6c 6f 61 64 45 6d 61 69 6c 2e 65 78 65 } //1 https://bitbucket.org/artanoGuima/onemore/downloads/payloadEmail.exe
		$a_01_3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 4d 6f 64 75 6c 65 2e 65 78 65 } //1 Start-Process 'WindowsDefenderModule.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}