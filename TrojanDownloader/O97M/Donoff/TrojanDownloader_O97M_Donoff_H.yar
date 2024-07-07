
rule TrojanDownloader_O97M_Donoff_H{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 73 65 20 36 35 20 54 6f 20 39 30 } //1 Case 65 To 90
		$a_01_1 = {29 20 4d 6f 64 20 32 36 29 20 2b 20 36 35 29 20 26 20 } //1 ) Mod 26) + 65) & 
		$a_01_2 = {43 61 73 65 20 39 37 20 54 6f 20 31 32 32 } //1 Case 97 To 122
		$a_01_3 = {29 20 4d 6f 64 20 32 36 29 20 2b 20 39 37 29 20 26 20 } //1 ) Mod 26) + 97) & 
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 = CreateObject(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_H_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3b 71 75 75 69 } //1 ;quui
		$a_00_1 = {22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 22 } //1 "C:\Users\Public\Documents"
		$a_00_2 = {26 20 22 5c 22 20 26 20 22 63 61 6c 63 2e 65 78 65 22 2c } //1 & "\" & "calc.exe",
		$a_00_3 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //1 Lib "urlmon" Alias "URLDownloadToFileA"
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_H_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 64 50 69 6e 4f 6b 30 5f 53 50 4c 28 55 73 65 72 46 6f 72 6d 32 2e 53 70 69 6e 42 75 74 74 6f 6e 31 2e } //1 StdPinOk0_SPL(UserForm2.SpinButton1.
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 41 31 2c 20 41 32 2c 20 41 33 29 } //1 = Replace(A1, A2, A3)
		$a_01_2 = {29 29 20 2f 20 28 31 32 20 2d 20 35 29 29 } //1 )) / (12 - 5))
		$a_01_3 = {28 38 38 20 2d 20 35 30 20 2d 20 33 33 29 2c 20 53 74 64 50 69 6e 4f 6b 30 5f 33 5f 31 2c } //1 (88 - 50 - 33), StdPinOk0_3_1,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_H_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 20 28 32 20 5e 20 28 38 20 2a 20 28 33 20 2d } //10 / (2 ^ (8 * (3 -
		$a_00_1 = {3d 20 31 20 54 68 65 6e 20 44 65 62 75 67 2e 41 73 73 65 72 74 20 4e 6f 74 20 } //1 = 1 Then Debug.Assert Not 
		$a_00_2 = {44 61 79 28 4e 6f 77 29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a } //1
		$a_00_3 = {44 6f 45 76 65 6e 74 73 0d 0a 44 65 62 75 67 2e 50 72 69 6e 74 20 31 20 2f 20 30 0d 0a } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Donoff_H_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {2b 20 31 3a 20 44 6f 45 76 65 6e 74 73 } //2 + 1: DoEvents
		$a_03_2 = {2e 54 65 78 74 42 6f 78 31 20 2b 20 90 05 0c 06 61 2d 7a 41 2d 5a 2e 54 65 78 74 42 6f 78 32 20 2b 20 90 1b 00 2e 54 65 78 74 42 6f 78 33 20 2b 90 00 } //3
		$a_01_3 = {2c 20 76 62 48 69 64 65 } //1 , vbHide
		$a_01_4 = {41 6c 65 6c 50 64 63 73 79 71 4f 65 51 47 70 72 } //3 AlelPdcsyqOeQGpr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3) >=10
 
}
rule TrojanDownloader_O97M_Donoff_H_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {2b 20 52 65 70 6c 61 63 65 28 22 73 62 73 74 61 72 74 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29 } //2 + Replace("sbstart.txt", "t", "e")
		$a_00_1 = {2c 20 52 65 70 6c 61 63 65 28 22 7a 70 65 6e 22 2c 20 22 7a 22 2c 20 22 4f 22 29 } //1 , Replace("zpen", "z", "O")
		$a_00_2 = {52 65 70 6c 61 63 65 28 22 72 45 4d 50 22 2c 20 22 72 22 2c 20 22 54 22 29 29 } //1 Replace("rEMP", "r", "T"))
		$a_00_3 = {3d 20 53 70 6c 69 74 28 75 72 6c 41 72 2c 20 22 20 22 29 } //1 = Split(urlAr, " ")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_H_7{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 41 31 2c 20 41 32 2c 20 41 33 29 } //1 = Replace(A1, A2, A3)
		$a_03_1 = {69 63 72 6f 90 02 03 6f 66 74 2e 58 90 02 03 4c 48 54 54 50 90 02 03 41 64 6f 64 62 2e 90 02 1f 2e 41 70 70 6c 69 63 61 74 69 6f 6e 90 02 03 57 90 02 03 63 72 69 70 74 2e 90 02 20 50 72 6f 63 90 00 } //1
		$a_01_2 = {22 43 22 20 41 6e 64 20 78 31 20 3c 3d 20 22 5a 22 20 41 6e 64 20 78 32 20 3d 20 22 3a 22 29 } //1 "C" And x1 <= "Z" And x2 = ":")
		$a_01_3 = {31 30 20 2d 20 28 32 20 2b 20 31 20 2b 20 32 29 29 } //1 10 - (2 + 1 + 2))
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_H_8{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 70 69 7a 2e 22 29 } //1 = StrReverse("piz.")
		$a_01_1 = {22 2d 45 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 20 65 6c 69 66 6f 72 70 6f 6e 2d } //1 "-E" & StrReverse(" eliforpon-
		$a_01_2 = {2e 43 6f 70 79 48 65 72 65 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 2d 63 6f 6d 20 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 29 2e 6e 61 6d 65 73 70 61 63 65 28 27 22 20 26 } //1 .CopyHere((new-object -com shell.application).namespace('" &
		$a_03_3 = {2e 52 75 6e 20 90 02 10 20 26 20 22 73 74 61 72 74 20 22 22 22 22 20 22 22 22 20 26 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_H_9{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 61 76 65 50 61 74 68 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 41 70 70 44 41 74 61 22 } //1 SavePath As String = "AppDAta"
		$a_01_1 = {46 75 6c 6c 53 61 76 65 50 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 53 61 76 65 50 61 74 68 29 20 26 20 22 5c 22 20 26 } //1 FullSavePath = Environ(SavePath) & "\" &
		$a_01_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 46 75 6c 6c 53 61 76 65 50 61 74 68 2c 20 32 } //1 .SaveToFile FullSavePath, 2
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 46 75 6c 6c 53 61 76 65 50 61 74 68 2c 20 76 62 4d 61 78 69 6d 69 7a 65 64 46 6f 63 75 73 29 } //1 Call Shell(FullSavePath, vbMaximizedFocus)
		$a_01_4 = {43 68 72 28 31 30 34 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 31 32 29 20 26 } //2 Chr(104) & Chr(116) & Chr(116) & Chr(112) &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}
rule TrojanDownloader_O97M_Donoff_H_10{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 workbook_open()
		$a_00_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Document_Open()
		$a_00_2 = {2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f } //1 .SpawnInstance_
		$a_00_3 = {2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 0d 0a 45 78 69 74 20 53 75 62 } //1
		$a_02_4 = {52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 2a 22 2c 20 22 22 29 90 00 } //1
		$a_02_5 = {52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 2c 22 2c 20 22 22 29 90 00 } //1
		$a_01_6 = {43 61 73 65 20 41 73 63 28 22 4e 22 29 20 2d 20 31 33 20 54 6f 20 41 73 63 28 22 5a 22 29 20 2d 20 31 33 } //1 Case Asc("N") - 13 To Asc("Z") - 13
		$a_00_7 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 Attribute VB_Name = "ThisDocument"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_H_11{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_02_0 = {22 68 74 74 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 7a 2e 90 02 10 2f 6d 6f 63 2e 90 02 1f 2f 2f 3a 70 22 29 20 26 20 22 69 70 22 90 00 } //2
		$a_02_1 = {22 25 41 50 50 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 2e 90 02 1f 22 29 20 26 20 22 78 65 22 90 00 } //2
		$a_01_2 = {22 2d 45 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 20 65 6c 69 66 6f 72 70 6f 6e 2d } //1 "-E" & StrReverse(" eliforpon-
		$a_01_3 = {22 66 6b 77 61 72 6e 69 6e 67 22 20 54 68 65 6e } //1 "fkwarning" Then
		$a_02_4 = {4b 69 6c 6c 90 01 2f 90 02 2f 2e 52 75 6e 20 90 1d 10 00 20 26 20 22 73 74 61 72 74 20 22 22 22 22 20 22 22 22 20 26 90 00 } //3
		$a_02_5 = {4b 69 6c 6c 20 90 1d 1f 00 20 26 20 90 1d 1f 00 28 90 10 02 00 29 90 02 0f 2e 52 75 6e 20 52 65 70 6c 61 63 65 28 90 1b 01 28 90 10 02 00 29 2c 90 02 1f 2c 20 90 1b 00 29 90 00 } //3
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*3+(#a_02_5  & 1)*3) >=8
 
}