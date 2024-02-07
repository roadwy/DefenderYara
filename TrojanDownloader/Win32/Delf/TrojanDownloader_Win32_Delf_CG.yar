
rule TrojanDownloader_Win32_Delf_CG{
	meta:
		description = "TrojanDownloader:Win32/Delf.CG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 73 79 73 74 65 6d 2e 65 78 65 } //01 00  c:\windows\system\system.exe
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 70 62 75 72 6f 2e 72 75 2f 63 6c 61 73 73 65 73 2f 66 64 73 2f 73 6d 61 73 68 2e 65 78 65 } //01 00  http://www.apburo.ru/classes/fds/smash.exe
		$a_00_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 6f 6d 61 6e 64 73 32 2e 65 78 65 } //01 00  c:\windows\system\comands2.exe
		$a_00_4 = {68 74 74 70 3a 2f 2f 73 61 6b 61 6e 67 2e 6e 65 74 2f 62 62 73 2f 69 63 6f 6e 2f 70 69 63 32 32 32 32 2e 6a 70 67 } //01 00  http://sakang.net/bbs/icon/pic2222.jpg
		$a_02_5 = {84 c0 74 0c 6a 00 68 90 01 02 44 00 e8 90 01 02 fb ff 68 c4 09 00 00 e8 90 01 02 fb ff ba 90 01 02 44 00 b8 90 01 02 44 00 e8 90 01 02 ff ff 84 c0 74 0c 6a 00 68 90 01 02 44 00 e8 90 01 02 fb ff 6a 00 68 90 01 02 44 00 e8 90 01 02 fb ff e8 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}