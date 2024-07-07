
rule TrojanDownloader_O97M_Obfuse_JU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 ("USERPROFILE")
		$a_01_1 = {22 75 73 65 72 70 72 6f 66 69 6c 65 22 } //1 "userprofile"
		$a_01_2 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 = New WshShell
		$a_03_3 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 10 2c 90 00 } //1
		$a_03_4 = {4f 70 65 6e 20 90 02 10 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //1
		$a_01_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 } //1 ActiveDocument.Bookmarks
		$a_01_6 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 63 65 70 74 41 6c 6c 52 65 76 69 73 69 6f 6e 73 53 68 6f 77 6e } //1 ActiveDocument.AcceptAllRevisionsShown
		$a_01_7 = {2e 53 68 6f 77 48 69 64 64 65 6e 20 3d 20 46 61 6c 73 65 } //1 .ShowHidden = False
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Obfuse_JU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 6c 69 74 2e 63 6f 6d 2e 6d 78 2f 78 6c 73 2f 6c 6f 68 6c 6f 67 2e 65 78 65 20 } //2 http://www.elit.com.mx/xls/lohlog.exe 
		$a_03_1 = {7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 90 02 0a 5c 90 02 0a 2e 65 78 65 90 00 } //2
		$a_03_2 = {68 74 74 70 3a 2f 2f 32 30 39 2e 31 34 31 2e 33 35 2e 32 33 39 2f 33 33 2f 90 02 0f 2e 6a 70 67 90 00 } //2
		$a_03_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 90 02 0f 2e 65 78 65 90 00 } //2
		$a_00_4 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 } //1 powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass  -command 
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JU_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 } //1 powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass  -command 
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 75 61 65 2d 73 69 67 6e 73 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 53 69 6d 70 6c 65 50 69 65 2f 43 6f 6e 74 65 6e 74 2f 70 72 6f 6a 65 63 74 31 2f 50 52 4f 4a 52 43 54 2d 42 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6a 6a 73 64 75 6c 6e 76 6a 2e 65 78 65 7d 3b 20 } //1 https://uae-signs.com/wp-includes/SimplePie/Content/project1/PROJRCT-B.exe -OutFile C:\Users\Public\Documents\jjsdulnvj.exe}; 
		$a_00_2 = {7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6a 6a 73 64 75 6c 6e 76 6a 2e 65 78 65 22 7d } //1 {Start-Process -FilePath "C:\Users\Public\Documents\jjsdulnvj.exe"}
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}