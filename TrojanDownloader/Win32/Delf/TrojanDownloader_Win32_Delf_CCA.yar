
rule TrojanDownloader_Win32_Delf_CCA{
	meta:
		description = "TrojanDownloader:Win32/Delf.CCA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 28 00 04 00 00 14 00 "
		
	strings :
		$a_02_0 = {ac fe c8 eb 01 90 01 01 c0 c0 98 eb 01 90 01 01 2a c1 f9 34 08 eb 01 90 01 01 f9 02 c1 eb 01 90 01 01 f9 f8 eb 01 90 01 01 c0 c0 72 fe c8 34 01 f8 2a c1 f8 eb 01 90 01 01 02 c1 2c 70 aa e2 cc 90 00 } //0a 00 
		$a_00_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 47 61 6d 65 53 65 74 75 70 2e 65 78 65 } //0a 00  shellexecute=GameSetup.exe
		$a_00_2 = {5c 6b 61 73 70 65 72 73 6b 79 2e 65 78 65 20 2f 69 } //0a 00  \kaspersky.exe /i
		$a_00_3 = {63 6d 64 20 2f 63 20 64 65 6c 20 2f 61 20 61 75 74 6f 72 75 6e 2e 69 6e 66 } //00 00  cmd /c del /a autorun.inf
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Delf_CCA_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.CCA,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 61 69 6c 2e 38 75 38 79 2e 63 6f 6d 2f 61 64 2f 70 69 63 2f 31 32 33 2e 74 78 74 } //01 00  http://mail.8u8y.com/ad/pic/123.txt
		$a_01_1 = {63 6d 64 20 2f 63 20 64 65 6c 20 2f 61 20 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  cmd /c del /a autorun.inf
		$a_01_2 = {5c 6b 61 73 70 65 72 73 6b 79 2e 65 78 65 20 2f 69 } //01 00  \kaspersky.exe /i
		$a_01_3 = {5c 77 69 6e 6c 6f 67 2e 74 78 74 } //01 00  \winlog.txt
		$a_01_4 = {5c 30 34 30 35 2e 74 78 74 } //01 00  \0405.txt
		$a_01_5 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 47 61 6d 65 53 65 74 75 70 2e 65 78 65 } //00 00  shellexecute=GameSetup.exe
	condition:
		any of ($a_*)
 
}