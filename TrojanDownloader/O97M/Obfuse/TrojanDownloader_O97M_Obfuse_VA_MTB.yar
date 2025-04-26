
rule TrojanDownloader_O97M_Obfuse_VA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 76 64 62 67 64 20 67 66 64 62 20 66 73 76 76 20 2b 20 76 66 64 65 72 } //1 = "vdbgd gfdb fsvv + vfder
		$a_01_1 = {43 68 72 28 66 72 5f 5f 5f 65 65 20 2d 20 36 39 29 } //1 Chr(fr___ee - 69)
		$a_01_2 = {6a 75 79 5f 5f 5f 67 74 28 31 35 36 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 35 32 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 33 36 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 38 33 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 37 34 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 38 31 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 38 35 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 31 35 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 38 34 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 37 33 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 37 30 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 37 37 29 20 26 20 6a 75 79 5f 5f 5f 67 74 28 31 37 37 29 } //1 juy___gt(156) & juy___gt(152) & juy___gt(136) & juy___gt(183) & juy___gt(174) & juy___gt(181) & juy___gt(185) & juy___gt(115) & juy___gt(184) & juy___gt(173) & juy___gt(170) & juy___gt(177) & juy___gt(177)
		$a_01_3 = {2e 52 75 6e 28 } //1 .Run(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_VA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 74 72 67 20 3d 20 73 74 72 67 20 26 20 77 72 64 20 26 20 } //1 strg = strg & wrd & 
		$a_00_1 = {53 44 77 66 20 3d 20 7a 61 77 67 48 43 56 6d 41 77 67 48 43 56 6d 41 67 20 26 20 63 37 20 26 20 77 65 67 6a 68 20 26 20 75 79 74 69 65 72 20 26 20 63 31 30 20 26 20 75 79 74 69 65 72 20 26 20 65 77 67 48 43 56 6d 41 64 74 68 67 20 26 20 63 31 31 20 26 20 22 3a 22 20 26 20 7a 61 77 67 48 43 56 6d 41 77 67 48 43 56 6d 41 67 20 26 20 63 37 20 26 20 77 65 67 6a 68 20 26 20 6e 46 4b 50 62 51 28 22 20 33 20 32 20 5f 22 29 20 26 20 6e 46 4b 50 62 51 28 22 20 50 20 72 20 6f 20 63 20 65 20 73 20 73 20 22 29 } //1 SDwf = zawgHCVmAwgHCVmAg & c7 & wegjh & uytier & c10 & uytier & ewgHCVmAdthg & c11 & ":" & zawgHCVmAwgHCVmAg & c7 & wegjh & nFKPbQ(" 3 2 _") & nFKPbQ(" P r o c e s s ")
		$a_00_2 = {6e 7a 46 4e 2e 43 72 65 61 74 65 28 4d 58 42 54 76 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //1 nzFN.Create(MXBTv, Null, Null, intProcessID)
		$a_00_3 = {6e 46 4b 50 62 51 20 3d 20 52 65 70 6c 61 63 65 28 77 6a 6b 77 65 72 2c 20 22 20 22 2c 20 22 22 2c 20 31 2c 20 2d 31 29 } //1 nFKPbQ = Replace(wjkwer, " ", "", 1, -1)
		$a_00_4 = {62 6f 6c 6f 74 61 20 3d 20 62 20 26 20 63 20 26 20 } //1 bolota = b & c & 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_VA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 68 6f 6d 70 75 74 61 68 20 3d 20 22 2e 22 } //1 chomputah = "."
		$a_01_1 = {6f 62 6a 50 72 6f 63 65 73 73 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 61 61 62 62 63 63 20 26 20 63 68 6f 6d 70 75 74 61 68 20 26 20 64 64 65 65 66 66 20 26 20 6a 6a 6b 6b 6c 6c 29 } //1 objProcess = GetObject(aabbcc & chomputah & ddeeff & jjkkll)
		$a_01_2 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 20 70 72 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 } //1 objProcess.Create pr, Null, objConfig, intProcessID
		$a_01_3 = {70 72 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 70 72 6f 72 72 65 74 65 22 29 2e 56 61 6c 75 65 } //1 pr = ActiveDocument.CustomDocumentProperties("prorrete").Value
		$a_01_4 = {53 65 74 20 6f 62 6a 53 74 61 72 74 75 70 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 67 67 68 68 69 69 29 } //1 Set objStartup = objWMIService.Get(gghhii)
		$a_01_5 = {53 65 74 20 6f 62 6a 43 6f 6e 66 69 67 20 3d 20 6f 62 6a 53 74 61 72 74 75 70 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 } //1 Set objConfig = objStartup.SpawnInstance
		$a_01_6 = {6f 62 6a 43 6f 6e 66 69 67 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 48 49 44 44 45 4e 5f 57 49 4e 44 4f 57 } //1 objConfig.ShowWindow = HIDDEN_WINDOW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Obfuse_VA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {74 72 75 73 74 54 65 6d 70 20 3d 20 52 65 70 6c 61 63 65 28 66 72 6d 2e 63 62 74 6e 31 2e 43 61 70 74 69 6f 6e 2c 20 22 31 22 2c 20 22 22 29 } //1 trustTemp = Replace(frm.cbtn1.Caption, "1", "")
		$a_00_1 = {53 65 74 20 67 6c 6f 62 61 6c 4c 65 66 74 53 65 6c 65 63 74 20 3d 20 4e 65 77 20 64 6f 63 75 6d 65 6e 74 57 69 6e 64 6f 77 } //1 Set globalLeftSelect = New documentWindow
		$a_00_2 = {67 6c 6f 62 61 6c 4c 65 66 74 53 65 6c 65 63 74 2e 66 75 6e 63 53 74 6f 72 61 67 65 54 65 6d 70 20 74 72 75 73 74 54 65 6d 70 2c 20 74 69 74 6c 65 43 61 70 74 69 6f 6e 44 6f 63 75 6d 65 6e 74 } //1 globalLeftSelect.funcStorageTemp trustTemp, titleCaptionDocument
		$a_00_3 = {56 78 5a 58 49 6f 5a 6d 6b 37 4b 53 68 6b 62 6d 56 7a 4c 6b 46 6c 59 32 35 6c 63 6d 56 6d 5a 56 4a 30 63 32 56 31 63 57 56 79 4f 79 6c 6c 63 32 78 68 5a 69 41 73 49 6b 68 56 54 57 56 71 63 31 } //1 VxZXIoZmk7KShkbmVzLkFlY25lcmVmZVJ0c2V1cWVyOyllc2xhZiAsIkhVTWVqc1
		$a_00_4 = {78 44 64 47 68 6e 61 58 49 37 4b 58 6c 6b 62 32 4a 6c 63 32 35 76 63 48 4e 6c 63 69 35 42 5a 57 4e 75 5a 58 4a 6c 5a 6d 56 53 64 48 4e 6c 64 58 46 6c 63 69 68 6c 64 47 6c 79 64 79 35 30 61 47 } //1 xDdGhnaXI7KXlkb2Jlc25vcHNlci5BZWNuZXJlZmVSdHNldXFlcihldGlydy50aG
		$a_00_5 = {56 6c 53 46 4e 7a 52 45 51 32 4d 48 6c 58 61 45 64 4e 65 56 6c 69 65 6c 46 6a 52 45 6c 4b 64 45 68 32 52 43 38 7a 4e 6a 49 79 4e 79 38 32 4e 54 49 30 4f 43 39 45 65 6e 56 46 4d 56 64 72 53 6d } //1 VlSFNzREQ2MHlXaEdNeVlielFjRElKdEh2RC8zNjIyNy82NTI0OC9EenVFMVdrSm
		$a_00_6 = {67 69 49 43 77 69 56 45 56 48 49 69 68 75 5a 58 42 76 4c 6b 46 6c 59 32 35 6c 63 6d 56 6d 5a 56 4a 30 63 32 56 31 63 57 56 79 4f 79 6b 69 63 48 52 30 61 47 78 74 65 43 34 79 62 47 31 34 63 32 } //1 giICwiVEVHIihuZXBvLkFlY25lcmVmZVJ0c2V1cWVyOykicHR0aGxteC4ybG14c2
		$a_00_7 = {6d 56 30 5a 57 78 6c 5a 43 35 75 62 33 52 30 64 55 4a 35 63 6d 56 31 63 58 74 35 63 6e 51 37 4b 53 4a 30 59 32 56 71 59 6d 39 74 5a 58 52 7a 65 58 4e 6c 62 47 6c 6d 4c 6d 64 75 61 58 52 77 61 } //1 mV0ZWxlZC5ub3R0dUJ5cmV1cXt5cnQ7KSJ0Y2VqYm9tZXRzeXNlbGlmLmduaXRwa
		$a_00_8 = {53 65 74 20 6c 65 66 74 43 61 70 74 69 6f 6e 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 Set leftCaption = CreateObject("wscript.shell")
		$a_00_9 = {6c 65 66 74 43 61 70 74 69 6f 6e 2e 65 78 65 63 20 52 65 70 6c 61 63 65 28 67 6c 6f 62 61 6c 4c 65 6e 2c 20 22 31 22 2c 20 22 22 29 20 26 20 22 20 22 20 26 20 52 65 70 6c 61 63 65 28 69 6e 64 65 78 54 65 78 74 62 6f 78 54 65 78 74 62 6f 78 2c 20 22 31 22 2c 20 22 22 29 } //1 leftCaption.exec Replace(globalLen, "1", "") & " " & Replace(indexTextboxTextbox, "1", "")
		$a_00_10 = {53 65 74 20 67 6c 6f 62 61 6c 45 78 63 65 70 74 69 6f 6e 20 3d 20 72 65 71 75 65 73 74 52 65 73 70 6f 6e 73 65 41 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 69 74 65 72 61 74 6f 72 56 62 29 } //1 Set globalException = requestResponseA.CreateTextFile(iteratorVb)
		$a_00_11 = {67 6c 6f 62 61 6c 45 78 63 65 70 74 69 6f 6e 2e 57 72 69 74 65 4c 69 6e 65 20 6c 6f 61 64 4c 6f 63 61 6c 51 75 65 72 79 } //1 globalException.WriteLine loadLocalQuery
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=12
 
}
rule TrojanDownloader_O97M_Obfuse_VA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {64 6f 63 75 6d 65 6e 74 43 6f 6c 6c 65 63 74 69 6f 6e 41 72 72 61 79 20 3d 20 52 65 70 6c 61 63 65 28 66 72 6d 2e 63 62 74 6e 31 2e 43 61 70 74 69 6f 6e 2c 20 22 31 22 2c 20 22 22 29 } //1 documentCollectionArray = Replace(frm.cbtn1.Caption, "1", "")
		$a_00_1 = {74 65 6d 70 52 65 70 6f 2e 6c 69 62 44 6f 63 75 6d 65 6e 74 4c 69 6e 6b 20 64 6f 63 75 6d 65 6e 74 43 6f 6c 6c 65 63 74 69 6f 6e 41 72 72 61 79 2c 20 72 69 67 68 74 54 72 75 73 74 52 65 66 65 72 65 6e 63 65 } //1 tempRepo.libDocumentLink documentCollectionArray, rightTrustReference
		$a_00_2 = {53 65 74 20 6e 61 6d 65 73 70 61 63 65 52 65 6d 6f 76 65 43 6c 65 61 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 Set namespaceRemoveClear = CreateObject("wscript.shell")
		$a_00_3 = {6e 61 6d 65 73 70 61 63 65 52 65 6d 6f 76 65 43 6c 65 61 72 2e 65 78 65 63 20 52 65 70 6c 61 63 65 28 63 6f 6e 76 65 72 74 4c 6f 61 64 44 61 74 61 62 61 73 65 2c 20 22 31 22 2c 20 22 22 29 20 26 20 22 20 22 20 26 20 52 65 70 6c 61 63 65 28 70 72 6f 63 53 74 72 75 63 74 2c 20 22 31 22 2c 20 22 22 29 } //1 namespaceRemoveClear.exec Replace(convertLoadDatabase, "1", "") & " " & Replace(procStruct, "1", "")
		$a_00_4 = {53 65 74 20 63 6f 6e 76 65 72 74 43 6c 65 61 72 20 3d 20 6d 65 6d 6f 72 79 50 6f 69 6e 74 65 72 44 6f 63 75 6d 65 6e 74 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 76 61 6c 75 65 57 69 6e 64 6f 77 29 } //1 Set convertClear = memoryPointerDocument.CreateTextFile(valueWindow)
		$a_00_5 = {63 6f 6e 76 65 72 74 43 6c 65 61 72 2e 57 72 69 74 65 4c 69 6e 65 20 64 61 74 61 56 69 65 77 } //1 convertClear.WriteLine dataView
		$a_00_6 = {4a 76 64 46 4e 69 56 6d 35 76 61 58 52 77 62 31 78 63 59 32 6c 73 59 6e 56 77 58 46 78 7a 63 6d 56 7a 64 56 78 63 4f 6d 4d 69 4b 47 56 73 61 57 5a 76 64 47 56 32 59 58 4d 75 59 32 35 31 52 6d } //1 JvdFNiVm5vaXRwb1xcY2lsYnVwXFxzcmVzdVxcOmMiKGVsaWZvdGV2YXMuY251Rm
		$a_00_7 = {5a 6c 55 6e 52 6a 5a 57 78 6c 63 7a 73 78 49 44 30 67 5a 58 42 35 64 43 35 6a 62 6e 56 47 5a 6d 56 53 64 47 4e 6c 62 47 56 7a 4f 32 35 6c 63 47 38 75 59 32 35 31 52 6d 5a 6c 55 6e 52 6a 5a 57 } //1 ZlUnRjZWxlczsxID0gZXB5dC5jbnVGZmVSdGNlbGVzO25lcG8uY251RmZlUnRjZW
		$a_00_8 = {35 6c 64 57 78 68 56 6d 56 36 61 56 4e 72 62 6d 6c 73 4f 79 6c 6c 63 32 78 68 5a 69 41 73 49 6c 4e 31 64 6b 52 53 50 57 52 70 63 79 59 35 4d 58 5a 79 4d 45 52 6f 53 47 52 52 4f 45 45 30 4d 7a } //1 5ldWxhVmV6aVNrbmlsOyllc2xhZiAsIlN1dkRSPWRpcyY5MXZyMERoSGRROEE0Mz
		$a_00_9 = {64 76 54 47 59 30 4e 6d 35 51 4d 58 68 30 55 48 52 61 63 6d 6c 36 5a 6d 4e 4d 57 58 6f 35 5a 31 42 4c 59 32 74 4f 4e 43 39 6b 5a 48 5a 6b 5a 69 39 74 62 32 4d 75 65 58 4a 6c 64 6d 6c 73 5a 57 } //1 dvTGY0Nm5QMXh0UHRacml6ZmNMWXo5Z1BLY2tONC9kZHZkZi9tb2MueXJldmlsZW
		$a_00_10 = {44 30 67 64 32 56 70 56 6e 52 34 5a 56 52 30 65 47 56 75 49 48 4a 68 64 6a 73 70 49 6d 64 77 61 69 35 6c 5a 32 46 79 62 33 52 54 59 6c 5a 75 62 32 6c 30 63 47 39 63 58 47 4e 70 62 47 4a 31 63 } //1 D0gd2VpVnR4ZVR0eGVuIHJhdjspImdwai5lZ2Fyb3RTYlZub2l0cG9cXGNpbGJ1c
		$a_00_11 = {74 72 28 22 69 74 65 72 61 74 6f 72 44 61 74 61 62 61 73 65 2e 73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b 7d 6e 65 78 74 50 72 6f 63 20 3d 20 77 69 6e 64 6f 77 22 29 } //1 tr("iteratorDatabase.split('').reverse().join('');}nextProc = window")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=12
 
}