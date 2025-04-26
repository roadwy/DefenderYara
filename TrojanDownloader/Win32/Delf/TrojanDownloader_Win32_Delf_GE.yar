
rule TrojanDownloader_Win32_Delf_GE{
	meta:
		description = "TrojanDownloader:Win32/Delf.GE,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0e 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_3 = {4d 61 63 72 6f 6d 65 64 69 61 20 46 6c 61 73 68 20 50 6c 61 79 65 72 20 49 6e 73 74 61 6c 61 64 6f 20 63 6f 6d 20 73 75 63 65 73 73 6f } //1 Macromedia Flash Player Instalado com sucesso
		$a_00_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 77 69 6e 64 6f 73 72 65 6d 6f 74 65 2e 65 78 65 } //1 C:\Windows\windosremote.exe
		$a_00_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 47 62 70 53 65 72 76 65 72 33 32 2e 65 78 65 } //1 C:\Windows\GbpServer32.exe
		$a_00_6 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 69 73 74 65 6d 61 73 2e 65 78 65 } //1 C:\Windows\sistemas.exe
		$a_00_7 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 55 70 64 61 74 65 64 61 74 61 2e 65 78 65 } //1 C:\Windows\WinUpdatedata.exe
		$a_02_8 = {68 74 74 70 3a 2f 2f [0-20] 63 6f 6d 2e 62 72 2f 77 69 6e 64 6f 73 72 65 6d 6f 74 65 2e 74 78 74 } //1
		$a_02_9 = {68 74 74 70 3a 2f 2f [0-20] 63 6f 6d 2e 62 72 2f 47 62 70 53 65 72 76 65 72 33 32 2e 74 78 74 } //1
		$a_02_10 = {68 74 74 70 3a 2f 2f [0-20] 63 6f 6d 2e 62 72 2f 57 69 6e 55 70 64 61 74 65 64 61 74 61 2e 74 78 74 } //1
		$a_00_11 = {41 70 6c 69 63 61 69 76 6f 20 64 6f 20 4d 53 2d 44 4f 53 } //1 Aplicaivo do MS-DOS
		$a_02_12 = {33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 ?? ?? ?? ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 ?? ?? ?? ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 ?? ?? ?? ff 33 c0 5a 59 59 64 89 10 } //1
		$a_02_13 = {33 d2 33 c0 e8 ?? ?? ff ff ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 45 00 e8 ?? ?? ff ff ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 45 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1+(#a_02_9  & 1)*1+(#a_02_10  & 1)*1+(#a_00_11  & 1)*1+(#a_02_12  & 1)*1+(#a_02_13  & 1)*1) >=23
 
}