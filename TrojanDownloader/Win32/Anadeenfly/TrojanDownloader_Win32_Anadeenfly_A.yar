
rule TrojanDownloader_Win32_Anadeenfly_A{
	meta:
		description = "TrojanDownloader:Win32/Anadeenfly.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 61 74 74 6c 79 44 6f 77 6e 6c 6f 61 64 5c 72 65 6c 65 61 73 65 5c 4e 61 74 74 6c 79 44 6f 77 6e 6c 6f 61 64 2e 70 64 62 } //01 00  NattlyDownload\release\NattlyDownload.pdb
		$a_01_1 = {63 00 6f 00 69 00 6e 00 69 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 66 00 69 00 6c 00 65 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 } //01 00  coinis.com/getfileinstall.php
		$a_01_2 = {4e 00 61 00 74 00 74 00 6c 00 79 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  NattlyDefender.exe
	condition:
		any of ($a_*)
 
}