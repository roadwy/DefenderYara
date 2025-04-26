
rule TrojanDownloader_O97M_Powdow_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 22 57 60 37 63 72 69 70 74 2e 60 37 68 65 6c 6c 22 2c 20 22 60 37 22 2c 20 22 73 22 29 29 } //1 = CreateObject(Replace("W`7cript.`7hell", "`7", "s"))
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 70 6f 77 60 37 72 73 68 60 37 6c 6c 20 22 2c 20 22 60 37 22 2c 20 22 65 22 29 } //1 = Replace("pow`7rsh`7ll ", "`7", "e")
		$a_01_2 = {48 31 48 39 2e 52 75 6e 20 28 48 34 48 36 20 2b 20 48 32 48 36 29 2c 20 30 2c 20 54 72 75 65 } //1 H1H9.Run (H4H6 + H2H6), 0, True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_BB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 22 57 5e 5e 63 72 69 70 74 2e 5e 5e 68 65 6c 6c 22 2c 20 22 5e 5e 22 2c 20 22 73 22 29 29 } //1 = CreateObject(Replace("W^^cript.^^hell", "^^", "s"))
		$a_01_1 = {48 38 48 37 20 3d 20 52 65 70 6c 61 63 65 28 22 70 6f 77 5e 5e 72 73 68 5e 5e 6c 6c 20 22 2c 20 22 5e 5e 22 2c 20 22 65 22 29 } //1 H8H7 = Replace("pow^^rsh^^ll ", "^^", "e")
		$a_01_2 = {48 38 48 32 2e 52 75 6e 20 28 48 38 48 37 20 2b 20 48 32 48 32 29 2c 20 30 2c 20 54 72 75 65 } //1 H8H2.Run (H8H7 + H2H2), 0, True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_BB_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-0c] 2c 20 [0-0c] 2c 20 32 29 29 29 } //1
		$a_01_1 = {3d 20 73 6f 49 66 78 31 38 6e 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 29 } //1 = soIfx18n(UserForm1.Label1.Caption)
		$a_01_2 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 2e 49 74 65 6d 28 22 70 61 72 61 6d 31 22 29 20 3d } //1 .Environment("process").Item("param1") =
		$a_01_3 = {2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 63 61 6c 6c 20 25 70 61 72 61 6d 31 25 22 2c 20 32 } //1 .run "cmd /c call %param1%", 2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_BB_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-0c] 2c 20 [0-0c] 2c 20 32 29 29 29 } //1
		$a_01_1 = {3d 20 77 5a 6a 54 68 48 37 78 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 29 } //1 = wZjThH7x(UserForm1.Label1.Caption)
		$a_01_2 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 2e 49 74 65 6d 28 22 70 61 72 61 6d 31 22 29 20 3d } //1 .Environment("process").Item("param1") =
		$a_01_3 = {2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 63 61 6c 6c 20 25 70 61 72 61 6d 31 25 22 2c 20 32 } //1 .run "cmd /c call %param1%", 2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_BB_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 67 6f 64 2e 22 20 26 } //1 = "C:\Users\Public\Documents\god." &
		$a_03_1 = {2e 57 72 69 74 65 4c 69 6e 65 20 [0-14] 20 26 20 [0-14] 20 26 20 22 20 2d 77 20 68 69 20 73 6c 5e 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 } //1
		$a_01_2 = {44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 6f 72 6e 65 78 69 73 74 2e 65 60 78 65 } //1 Dest C:\Users\Public\Documents\bornexist.e`xe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_BB_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 63 3a 5c 74 65 6d 70 5c 73 70 6f 6f 6c 2e 65 78 65 22 29 } //1 Shell ("powershell.exe c:\temp\spool.exe")
		$a_01_1 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 6d 6b 64 69 72 20 63 3a 5c 74 65 6d 70 22 29 } //1 Shell ("powershell.exe mkdir c:\temp")
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 26 2c 20 73 53 6f 75 72 63 65 55 72 6c 2c 20 73 4c 6f 63 61 6c 46 69 6c 65 2c 20 42 49 4e 44 46 5f 47 45 54 4e 45 57 45 53 54 56 45 52 53 49 4f 4e 2c 20 30 26 29 } //1 DownloadFile = URLDownloadToFile(0&, sSourceUrl, sLocalFile, BINDF_GETNEWESTVERSION, 0&)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_BB_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 .createElement("b64")
		$a_03_1 = {28 53 74 72 52 65 76 65 72 73 65 28 22 70 6d 65 74 22 29 29 20 26 20 22 5c [0-05] 2e 74 6d 70 22 } //1
		$a_03_2 = {2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 90 0c 02 00 2e 54 65 78 74 } //1
		$a_03_3 = {2e 43 72 65 61 74 65 20 [0-08] 28 29 20 2b 20 22 20 22 20 2b } //1
		$a_01_4 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 20 5f } //1 Alias "URLDownloadToFileA" ( _
		$a_03_5 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-03] 29 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}