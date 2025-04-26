
rule TrojanDownloader_O97M_Donoff_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 60 70 73 3a 2f 2f 76 65 72 73 37 37 38 76 65 32 39 2e 63 6f 6d 2f 70 65 74 61 6c 6f 2e 6a 60 70 67 } //1 htt`ps://vers778ve29.com/petalo.j`pg
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 41 64 64 20 22 4d 73 48 74 22 } //1 .Add "MsHt"
		$a_01_1 = {2e 41 64 64 20 22 61 20 68 74 74 70 3a 2f 2f 22 } //1 .Add "a http://"
		$a_01_2 = {2e 41 64 64 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 6b 6a 61 73 64 68 73 75 64 69 71 6f 77 69 75 64 71 77 22 } //1 .Add "bitly.com/asdkjasdhsudiqowiudqw"
		$a_01_3 = {6f 62 6a 2e 4d 61 69 6e 43 61 6c 6c 65 78 20 28 64 64 31 20 2b 20 64 64 32 20 2b 20 64 64 33 29 } //1 obj.MainCallex (dd1 + dd2 + dd3)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 20 3d 20 22 6d 73 68 74 61 } //1 X = "mshta
		$a_01_1 = {58 20 3d 20 22 6d 73 68 74 61 2e 65 60 78 60 65 20 22 } //1 X = "mshta.e`x`e "
		$a_01_2 = {59 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //1 Y = "https://www.bitly.com/"
		$a_03_3 = {5a 20 3d 20 22 [0-aa] 22 } //1
		$a_01_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 53 68 65 6c 6c 28 58 20 2b 20 59 20 2b 20 5a 29 29 } //1 Debug.Print (Shell(X + Y + Z))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 63 62 20 3d 20 22 76 62 78 63 62 20 62 6e 76 62 63 76 20 63 7a 78 63 20 76 78 63 62 76 78 63 62 22 } //1 ncb = "vbxcb bnvbcv czxc vxcbvxcb"
		$a_01_1 = {76 78 63 78 62 20 3d 20 22 76 78 63 62 20 62 78 63 62 20 63 62 76 63 78 62 22 } //1 vxcxb = "vxcb bxcb cbvcxb"
		$a_01_2 = {78 63 76 62 76 78 63 20 3d 20 22 76 78 76 62 76 20 63 78 66 67 68 20 63 62 63 6e 20 62 6e 63 76 62 6e 73 64 67 67 20 34 74 34 72 74 20 63 20 66 67 73 67 62 22 } //1 xcvbvxc = "vxvbv cxfgh cbcn bncvbnsdgg 4t4rt c fgsgb"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 20 3d 20 22 6d 73 68 74 61 2e 65 78 65 20 22 } //1 X = "mshta.exe "
		$a_01_1 = {59 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //1 Y = "https://www.bitly.com/"
		$a_01_2 = {5a 20 3d 20 22 6b 64 64 6a 6b 64 77 6f 6b 64 64 77 6f 64 6b 77 6f 64 6b 69 22 } //1 Z = "kddjkdwokddwodkwodki"
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 53 68 65 6c 6c 28 58 20 2b 20 59 20 2b 20 5a 29 29 } //1 Debug.Print (Shell(X + Y + Z))
		$a_01_4 = {41 75 74 6f 5f 4f 70 65 6e } //1 Auto_Open
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 6a 69 6f 72 72 20 3d 20 22 68 22 20 26 20 22 65 22 20 26 20 22 6c 22 20 26 20 22 6c 22 } //1 fjiorr = "h" & "e" & "l" & "l"
		$a_01_1 = {45 55 72 78 72 58 4f 20 3d 20 22 53 22 20 26 20 66 6a 69 6f 72 72 } //1 EUrxrXO = "S" & fjiorr
		$a_01_2 = {61 48 69 4d 4e 20 3d 20 22 57 22 20 26 20 22 53 22 20 26 20 22 63 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 70 22 20 26 20 22 74 22 } //1 aHiMN = "W" & "S" & "c" & "r" & "i" & "p" & "t"
		$a_01_3 = {62 62 77 74 70 54 56 56 20 3d 20 61 48 69 4d 4e 20 26 20 22 2e 22 20 26 20 45 55 72 78 72 58 4f } //1 bbwtpTVV = aHiMN & "." & EUrxrXO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 6f 79 75 6b 69 75 20 3d 20 43 68 72 28 63 64 73 73 66 20 2d 20 31 31 36 29 } //1 ioyukiu = Chr(cdssf - 116)
		$a_00_1 = {50 44 46 4e 61 6d 65 20 3d 20 4c 65 66 74 28 70 70 74 4e 61 6d 65 2c 20 49 6e 53 74 72 28 70 70 74 4e 61 6d 65 2c 20 22 2e 22 29 29 20 26 20 22 70 64 66 22 } //1 PDFName = Left(pptName, InStr(pptName, ".")) & "pdf"
		$a_00_2 = {3d 20 22 62 64 68 67 66 20 20 62 67 66 62 20 37 38 39 } //1 = "bdhgf  bgfb 789
		$a_00_3 = {74 65 72 67 20 75 79 74 69 20 67 72 20 64 68 20 6a 79 20 66 65 } //1 terg uyti gr dh jy fe
		$a_00_4 = {57 53 43 72 69 70 74 2e 73 68 65 6c 6c } //1 WSCript.shell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 64 66 78 63 20 3d 20 22 62 76 63 76 68 67 6a 20 20 63 76 6e 76 63 66 68 20 63 76 6e 76 68 67 6b 22 } //1 sdfxc = "bvcvhgj  cvnvcfh cvnvhgk"
		$a_01_1 = {6c 6a 6b 6e 6d 6e 20 3d 20 43 68 72 28 6f 70 68 6a 69 20 2d 20 31 33 30 29 } //1 ljknmn = Chr(ophji - 130)
		$a_01_2 = {76 63 78 62 64 67 20 3d 20 22 76 78 76 62 78 64 66 67 20 63 78 66 67 68 20 76 63 76 6e 20 67 66 67 68 20 2c 76 62 6e 76 63 20 63 76 63 76 6e 22 } //1 vcxbdg = "vxvbxdfg cxfgh vcvn gfgh ,vbnvc cvcvn"
		$a_01_3 = {66 64 73 61 66 20 3d 20 22 63 78 76 78 20 63 62 62 63 76 78 20 76 63 78 7a 76 73 64 66 20 66 64 61 73 78 63 76 22 } //1 fdsaf = "cxvx cbbcvx vcxzvsdf fdasxcv"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6c 42 47 72 20 3d 20 22 6a 69 72 61 2e 74 78 74 } //1 slBGr = "jira.txt
		$a_01_1 = {43 62 45 57 6d 4f 64 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 22 63 22 20 26 20 22 73 22 20 26 20 22 63 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 70 22 20 26 20 22 74 22 20 26 20 22 20 2f 2f 45 3a 6a 73 63 72 69 70 74 20 22 20 26 20 76 42 50 73 54 4f 49 29 2c 20 30 } //1 CbEWmOd.CreateObject("WScript.Shell").Run ("c" & "s" & "c" & "r" & "i" & "p" & "t" & " //E:jscript " & vBPsTOI), 0
		$a_01_2 = {54 47 7a 6c 62 43 41 2e 53 61 76 65 54 6f 46 69 6c 65 20 73 6c 42 47 72 2c 20 32 } //1 TGzlbCA.SaveToFile slBGr, 2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 34 30 2e 38 32 2e 33 33 2e 36 39 2f 63 68 69 6d 2e 65 78 65 } //1 http://140.82.33.69/chim.exe
		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 22 } //1 Environ("AppData") & "\Microsoft\Windows\Start Menu\Programs\Startup\"
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 CreateObject("Microsoft.XMLHTTP")
		$a_01_3 = {73 63 68 65 64 75 6c 65 72 2e 65 78 65 } //1 scheduler.exe
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_00_0 = {65 6e 63 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 65 6e 63 29 } //1 enc = StrReverse(enc)
		$a_00_1 = {4a 20 3d 20 4d 69 64 28 65 6e 63 2c 20 69 2c 20 31 29 } //1 J = Mid(enc, i, 1)
		$a_00_2 = {41 70 70 44 61 74 61 20 3d 20 41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 4a 29 20 2d 20 31 29 } //1 AppData = AppData & Chr(Asc(J) - 1)
		$a_00_3 = {4f 70 65 6e 20 22 67 65 74 22 2c 20 } //1 Open "get", 
		$a_00_4 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //5 = Chr(50) + Chr(48) + Chr(48)
		$a_00_5 = {53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 Shell.Application
		$a_00_6 = {55 6e 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 64 6f 63 75 6d 65 6e 74 } //1 Unable to open document
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*5+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 61 6d 61 6b 68 2e 48 6f 6f 74 69 79 61 5a } //1 Shamakh.HootiyaZ
		$a_01_1 = {4d 61 76 69 79 61 31 20 3d 20 79 61 7a 65 65 64 31 20 2b 20 79 61 7a 65 65 64 32 20 2b 20 79 61 7a 65 65 64 33 20 2b 20 79 61 7a 65 65 64 34 20 2b 20 22 20 22 20 2b 20 79 61 7a 65 65 64 35 20 2b 20 79 61 7a 65 65 64 35 35 20 2b 20 79 61 7a 65 65 64 36 36 } //1 Maviya1 = yazeed1 + yazeed2 + yazeed3 + yazeed4 + " " + yazeed5 + yazeed55 + yazeed66
		$a_01_2 = {63 61 72 69 6e 74 65 72 66 61 63 65 5f 6e 61 6d 65 20 28 4d 61 76 69 79 61 31 29 } //1 carinterface_name (Maviya1)
		$a_01_3 = {53 68 65 6c 6c 20 69 5f 6e 61 6d 65 } //1 Shell i_name
		$a_03_4 = {48 6f 6f 74 69 79 61 5a 28 29 [0-03] 44 69 6d 20 79 61 7a 65 65 64 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 20 3d 20 22 68 74 74 70 3a 2f 2f 73 71 6c 73 72 76 30 34 2f 52 65 70 6f 72 74 53 65 72 76 65 72 3f 2f 4c 4e 25 32 30 52 65 70 6f 72 74 73 2f 45 78 70 6f 72 74 25 32 30 4d 41 52 2f 41 6e 6f 64 65 6e 70 6c 61 6e 75 6e 67 26 72 73 3a 46 6f 72 6d 61 74 3d 45 58 43 45 4c 4f 50 45 4e 58 4d 4c 22 } //1 url = "http://sqlsrv04/ReportServer?/LN%20Reports/Export%20MAR/Anodenplanung&rs:Format=EXCELOPENXML"
		$a_01_1 = {73 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 4d 65 2e 50 61 74 68 20 26 20 22 5c 41 6e 6f 64 65 6e 70 6c 61 6e 75 6e 67 2e 78 6c 73 78 22 2c 20 32 } //1 stream.SaveToFile Me.Path & "\Anodenplanung.xlsx", 2
		$a_01_2 = {4b 69 6c 6c 20 4d 65 2e 50 61 74 68 20 26 20 22 5c 41 6e 6f 64 65 6e 70 6c 61 6e 75 6e 67 2e 78 6c 73 78 22 } //1 Kill Me.Path & "\Anodenplanung.xlsx"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 37 20 2f 20 32 37 20 2f 20 32 30 32 31 } //1 = 7 / 27 / 2021
		$a_01_1 = {53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 Shell.Application
		$a_01_2 = {47 65 74 74 69 6e 67 20 72 65 73 6f 75 63 72 63 65 73 20 74 6f 20 64 69 73 70 6c 61 79 20 73 70 72 65 65 64 73 68 65 65 74 22 2c 20 2c 20 22 57 61 72 6e 69 6e 67 22 } //1 Getting resoucrces to display spreedsheet", , "Warning"
		$a_01_3 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("WScript.Shell")
		$a_01_5 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 22 } //1 Environ$("USERPROFILE") & "\"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 20 3d 20 22 63 6d 64 20 2f 63 20 63 64 20 2f 64 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 20 26 26 20 74 79 70 65 20 22 22 22 20 2b 20 2e 46 75 6c 6c 4e 61 6d 65 20 2b 20 22 22 22 20 7c 20 66 69 6e 64 73 74 72 20 2f 72 20 22 22 5e 76 61 72 22 22 20 3e 20 79 2e 6a 73 20 26 26 20 77 73 63 72 69 70 74 20 79 2e 6a 73 20 22 22 22 20 2b 20 2e 46 75 6c 6c 4e 61 6d 65 20 2b 20 } //1 s = "cmd /c cd /d %USERPROFILE% && type """ + .FullName + """ | findstr /r ""^var"" > y.js && wscript y.js """ + .FullName + 
		$a_01_1 = {6e 20 3d 20 53 68 65 6c 6c 28 73 2c 20 76 62 48 69 64 65 29 } //1 n = Shell(s, vbHide)
		$a_01_2 = {2e 43 6f 6e 74 65 6e 74 2e 46 6f 6e 74 2e 43 6f 6c 6f 72 49 6e 64 65 78 20 3d 20 77 64 42 6c 61 63 6b } //1 .Content.Font.ColorIndex = wdBlack
		$a_01_3 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e } //1 Document_Open
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {42 61 53 74 72 20 3d 20 44 65 63 6f 64 65 36 34 28 [0-15] 28 29 29 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_1 = {53 68 65 6c 6c 28 22 72 65 67 73 76 72 33 32 20 2f 73 20 22 20 26 20 66 69 6c 65 50 61 74 68 29 [0-03] 45 6e 64 20 53 75 62 } //1
		$a_01_2 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 42 65 66 6f 72 65 43 6c 6f 73 65 28 43 61 6e 63 65 6c 20 61 73 20 42 6f 6f 6c 65 61 6e 29 } //1 Private Sub Workbook_BeforeClose(Cancel as Boolean)
		$a_01_3 = {43 61 6c 6c 20 52 65 64 75 63 65 4f 6e 6c 69 6e 65 28 29 } //1 Call ReduceOnline()
		$a_03_4 = {5c 6e 6f 77 2e 64 6c 6c 22 90 0a 23 00 70 61 74 68 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 34 36 2e 33 30 2e 31 38 38 2e 31 39 30 2f 77 65 62 64 61 76 2f 74 61 73 6b 68 6f 73 74 2e 65 78 65 } //1 http://46.30.188.190/webdav/taskhost.exe
		$a_01_1 = {22 43 3a 5c 55 73 65 72 73 5c 22 20 2b 20 75 73 65 72 6e 61 6d 65 20 2b 20 22 5c 56 69 64 65 6f 73 5c 74 61 73 6b 68 6f 73 74 2e 65 78 65 22 2c 20 32 20 27 20 31 20 3d 20 6e 6f 20 6f 76 65 72 77 72 69 74 65 2c 20 32 20 3d 20 6f 76 65 72 77 72 69 74 65 } //1 "C:\Users\" + username + "\Videos\taskhost.exe", 2 ' 1 = no overwrite, 2 = overwrite
		$a_01_2 = {68 74 74 70 3a 2f 2f 34 36 2e 33 30 2e 31 38 38 2e 31 39 30 2f 77 65 62 64 61 76 2f 73 74 61 74 75 73 2e 74 78 74 } //1 http://46.30.188.190/webdav/status.txt
		$a_01_3 = {22 43 3a 5c 55 73 65 72 73 5c 22 20 2b 20 75 73 65 72 6e 61 6d 65 20 2b 20 22 5c 56 69 64 65 6f 73 5c 73 74 61 74 75 73 2e 62 61 74 22 2c 20 32 20 27 20 31 20 3d 20 6e 6f 20 6f 76 65 72 77 72 69 74 65 2c 20 32 20 3d 20 6f 76 65 72 77 72 69 74 65 } //1 "C:\Users\" + username + "\Videos\status.bat", 2 ' 1 = no overwrite, 2 = overwrite
		$a_01_4 = {78 20 3d 20 53 68 65 6c 6c 28 50 61 74 68 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 x = Shell(Path, vbNormalFocus)
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 42 61 74 } //1 DownloadBat
		$a_01_7 = {45 6e 76 69 72 6f 6e 28 22 75 73 65 72 6e 61 6d 65 22 29 } //1 Environ("username")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0c 00 00 "
		
	strings :
		$a_01_0 = {61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 66 69 6c 65 2e 64 61 74 22 } //1 a = Environ("Temp") & "\file.dat"
		$a_01_1 = {62 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 73 75 72 76 65 79 2e 64 61 74 22 } //1 b = Environ("Temp") & "\survey.dat"
		$a_01_2 = {64 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 73 75 72 76 65 79 2e 64 61 74 2e 6c 6f 67 31 22 } //1 d = Environ("Temp") & "\survey.dat.log1"
		$a_01_3 = {61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 6f 75 74 70 75 74 2e 64 61 74 22 } //1 a = Environ("Temp") & "\output.dat"
		$a_01_4 = {62 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 6f 75 74 70 75 74 2e 64 61 74 2e 6c 6f 67 22 } //1 b = Environ("Temp") & "\output.dat.log"
		$a_01_5 = {64 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 73 75 72 76 65 79 2e 64 61 74 2e 6c 6f 67 32 22 } //1 d = Environ("Temp") & "\survey.dat.log2"
		$a_01_6 = {53 65 74 20 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set s = CreateObject("WScript.Shell")
		$a_01_7 = {73 2e 45 78 65 63 20 64 } //1 s.Exec d
		$a_01_8 = {62 69 6e 2e 62 61 73 65 36 34 } //1 bin.base64
		$a_01_9 = {53 61 76 65 54 6f 46 69 6c 65 20 61 } //1 SaveToFile a
		$a_01_10 = {68 74 74 70 3a 2f 2f 65 63 32 2d 33 2d 36 36 2d 32 31 33 2d 35 37 2e 65 75 2d 63 65 6e 74 72 61 6c 2d 31 2e 63 6f 6d 70 75 74 65 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 73 74 61 6e 64 61 72 64 63 68 61 72 74 65 72 65 64 } //1 http://ec2-3-66-213-57.eu-central-1.compute.amazonaws.com/standardchartered
		$a_01_11 = {41 63 74 69 76 65 53 68 65 65 74 2e 52 61 6e 67 65 28 22 45 37 22 2c 20 22 45 31 36 22 29 2e 4c 6f 63 6b 65 64 20 3d 20 54 72 75 65 } //1 ActiveSheet.Range("E7", "E16").Locked = True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Donoff_SM_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 6a 4c 75 77 52 57 64 6a 20 3d 20 41 72 72 61 79 28 22 73 68 6c 53 44 6e 6d 63 22 2c 20 22 72 74 6b 7a 55 5a 6f 4f 22 2c 20 22 69 6a 56 5a 4b 69 54 54 22 2c 20 22 6f 54 41 77 6b 6e 6c 45 22 2c 20 22 6c 71 6a 71 4f 54 56 7a 22 29 } //1 ojLuwRWdj = Array("shlSDnmc", "rtkzUZoO", "ijVZKiTT", "oTAwknlE", "lqjqOTVz")
		$a_01_1 = {4d 74 72 69 49 56 54 4a 57 20 3d 20 41 72 72 61 79 28 22 66 52 69 42 44 56 4a 4f 22 2c 20 22 52 69 6b 6e 6e 73 44 49 22 2c 20 22 66 4f 64 73 7a 41 4b 4f 22 2c 20 22 59 4d 52 72 70 4c 53 7a 22 2c 20 22 71 62 45 57 44 44 68 56 22 29 } //1 MtriIVTJW = Array("fRiBDVJO", "RiknnsDI", "fOdszAKO", "YMRrpLSz", "qbEWDDhV")
		$a_01_2 = {58 63 7a 70 6c 4a 5a 41 6f 20 3d 20 41 72 72 61 79 28 22 57 64 48 71 52 5a 69 47 22 2c 20 22 54 63 71 44 52 59 46 4c 22 2c 20 22 6b 77 4c 6e 68 45 62 68 22 2c 20 22 48 55 56 44 56 64 4f 6e 22 2c 20 22 52 44 53 69 4c 4a 59 43 22 29 } //1 XczplJZAo = Array("WdHqRZiG", "TcqDRYFL", "kwLnhEbh", "HUVDVdOn", "RDSiLJYC")
		$a_01_3 = {53 68 65 6c 6c 24 20 45 55 69 6f 75 42 4e 6e 6a 2c 20 30 } //2 Shell$ EUiouBNnj, 0
		$a_01_4 = {61 50 6a 62 71 53 46 44 72 20 3d 20 41 72 72 61 79 28 22 64 41 4e 4e 4e 47 52 42 22 2c 20 22 5a 69 77 44 62 6c 71 4e 22 2c 20 22 44 6d 4f 47 58 41 62 58 22 2c 20 22 4a 4e 52 56 41 71 6f 4f 22 2c 20 22 53 4d 72 64 42 61 44 77 22 29 } //1 aPjbqSFDr = Array("dANNNGRB", "ZiwDblqN", "DmOGXAbX", "JNRVAqoO", "SMrdBaDw")
		$a_01_5 = {42 6a 6c 61 62 7a 77 69 74 20 3d 20 41 72 72 61 79 28 22 4e 6e 6a 72 7a 54 64 59 22 2c 20 22 70 44 41 70 77 41 6a 74 22 2c 20 22 69 6c 50 74 4e 4c 63 69 22 2c 20 22 52 46 72 50 42 76 4b 4f 22 2c 20 22 6e 62 6d 43 49 57 56 73 22 29 } //1 Bjlabzwit = Array("NnjrzTdY", "pDApwAjt", "ilPtNLci", "RFrPBvKO", "nbmCIWVs")
		$a_01_6 = {4f 45 4d 57 44 48 45 66 42 20 3d 20 41 72 72 61 79 28 22 6a 74 4e 69 6b 6a 42 4c 22 2c 20 22 7a 5a 72 63 4e 58 74 74 22 2c 20 22 6c 43 55 4f 6a 6c 4c 50 22 2c 20 22 57 66 49 7a 46 66 4b 41 22 2c 20 22 4c 4e 55 43 77 66 43 76 22 29 } //1 OEMWDHEfB = Array("jtNikjBL", "zZrcNXtt", "lCUOjlLP", "WfIzFfKA", "LNUCwfCv")
		$a_01_7 = {4a 42 6a 54 64 64 62 5a 43 20 3d 20 64 42 51 42 77 4a 64 6b 51 4a 20 2b 20 75 4d 69 4b 50 4e 20 2b 20 7a 4e 6b 6d 48 20 2b 20 6f 52 48 6c 59 63 57 20 2b 20 66 59 74 46 63 6f 70 4f 20 2b 20 6f 4b 4d 44 6b 20 2b 20 70 6d 42 6e 59 4e 68 43 20 2b 20 44 59 76 75 51 63 69 6a 20 2b 20 45 72 52 49 66 50 6b 6c 7a 49 20 2b 20 5a 64 55 6b 7a 50 53 73 4f 54 20 2b 20 6b 63 4a 44 64 4e 4e 75 52 4e 20 2b 20 51 72 64 51 72 6c 54 74 46 6c 20 2b 20 6d 6b 42 76 6a 58 43 69 20 2b 20 59 7a 77 57 61 72 20 2b 20 6d 50 44 6a 76 49 62 4a 20 2b 20 57 4b 6c 4a 69 4e 6d 61 4a 69 } //1 JBjTddbZC = dBQBwJdkQJ + uMiKPN + zNkmH + oRHlYcW + fYtFcopO + oKMDk + pmBnYNhC + DYvuQcij + ErRIfPklzI + ZdUkzPSsOT + kcJDdNNuRN + QrdQrlTtFl + mkBvjXCi + YzwWar + mPDjvIbJ + WKlJiNmaJi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}