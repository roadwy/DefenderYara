
rule TrojanDropper_Win32_Delf_DJ{
	meta:
		description = "TrojanDropper:Win32/Delf.DJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {4b 75 d8 8d 45 e4 b9 90 01 02 41 00 8b 15 90 01 02 41 00 e8 90 01 02 ff ff 8b 55 e4 a1 90 01 02 41 00 e8 90 01 02 ff ff a1 90 01 02 41 00 e8 90 01 02 ff ff 8b c6 e8 90 01 02 ff ff 6a 01 68 90 01 02 41 00 68 90 01 02 41 00 8d 45 e0 b9 90 01 02 41 00 8b 15 90 01 02 41 00 e8 90 01 02 ff ff 8b 45 e0 e8 90 01 02 ff ff 50 68 90 01 02 41 00 a1 90 01 02 41 00 50 e8 90 01 02 ff ff 6a 00 68 90 01 02 41 00 68 90 01 02 41 00 8d 45 dc b9 90 01 02 41 00 8b 15 90 01 02 41 00 e8 90 01 02 ff ff 8b 45 dc e8 90 01 02 ff ff 50 68 90 01 02 41 00 a1 90 01 02 41 00 50 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 00 } //01 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 57 65 62 20 46 6f 6c 64 65 72 73 } //01 00  C:\Program Files\Common Files\Microsoft Shared\Web Folders
		$a_00_3 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  \svchost.exe
		$a_00_4 = {5c 76 62 72 75 6e 33 32 2e 65 78 65 } //00 00  \vbrun32.exe
	condition:
		any of ($a_*)
 
}