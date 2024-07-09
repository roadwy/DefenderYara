
rule TrojanDownloader_Win32_Small_KX{
	meta:
		description = "TrojanDownloader:Win32/Small.KX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //1 Software\Borland\Delphi\Locales
		$a_00_1 = {63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 66 20 2d 74 20 31 35 20 2d 63 20 22 45 72 72 6f 20 49 6e 74 65 72 6e 6f 20 64 6f 20 57 69 6e 64 6f 77 73 } //1 cmd /c shutdown -r -f -t 15 -c "Erro Interno do Windows
		$a_00_2 = {6e 6f 67 75 69 20 43 3a 5c 73 79 73 74 65 6d 58 38 36 2e 74 78 74 } //1 nogui C:\systemX86.txt
		$a_00_3 = {6d 73 6e 6d 73 67 73 67 72 73 2e 65 78 65 } //1 msnmsgsgrs.exe
		$a_00_4 = {37 00 43 00 45 00 46 00 37 00 35 00 41 00 35 00 33 00 38 00 46 00 46 00 34 00 46 00 46 00 38 00 35 00 46 00 38 00 45 00 44 00 46 00 } //1 7CEF75A538FF4FF85F8EDF
		$a_03_5 = {b9 00 00 00 00 e8 ?? ?? fe ff 8b 45 ?? e8 ?? ?? fe ff 8b f0 8d 45 ?? e8 ?? ?? ff ff 8d 45 ?? 50 8d 4d ?? ba ?? ?? 41 00 b8 ?? ?? 41 00 e8 ?? ?? ff ff 8b 55 ?? 58 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}