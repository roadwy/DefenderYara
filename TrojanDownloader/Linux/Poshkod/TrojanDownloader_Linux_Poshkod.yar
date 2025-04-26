
rule TrojanDownloader_Linux_Poshkod{
	meta:
		description = "TrojanDownloader:Linux/Poshkod,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_01_1 = {3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 63 68 72 75 70 64 61 74 65 2e 70 73 31 } //1 = "C:\Windows\Temp\chrupdate.ps1
		$a_01_2 = {77 77 77 2e 69 6c 61 75 6e 63 68 6d 61 6e 61 67 65 72 2e 63 6f 6d 2f 78 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 66 62 2d 69 6e 66 69 6c 74 72 61 74 6f 72 2d 70 65 72 73 6f 6e 61 6c 2f 64 6c 32 2e 70 68 70 } //1 www.ilaunchmanager.com/x/wp-content/plugins/fb-infiltrator-personal/dl2.php
		$a_00_3 = {3d 20 53 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 6c 6f 67 6f 20 2d 66 69 6c 65 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 63 68 72 75 70 64 61 74 65 2e 70 73 31 22 2c 20 76 62 48 69 64 65 29 } //1 = Shell("powershell.exe -nologo -file C:\Windows\Temp\chrupdate.ps1", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}