
rule TrojanDownloader_Win32_Banload_HH{
	meta:
		description = "TrojanDownloader:Win32/Banload.HH,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 08 00 00 04 00 "
		
	strings :
		$a_03_0 = {81 3f 7b 73 6b 7d 74 90 01 01 8a 07 30 c8 28 e8 aa 4a 75 90 00 } //03 00 
		$a_03_1 = {8b 45 fc 81 38 78 78 78 78 75 05 e9 90 01 02 00 00 90 00 } //02 00 
		$a_03_2 = {6a 00 6a 00 6a 06 e8 90 01 04 50 68 ff 00 00 00 68 90 01 04 e8 90 01 04 6a 00 6a 00 6a 07 e8 90 01 04 50 68 ff 00 00 00 90 00 } //01 00 
		$a_01_3 = {25 77 69 6e 64 69 72 25 5c 44 6f 77 6e 6c 6f 61 64 65 64 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 67 62 } //01 00  %windir%\Downloaded Program Files\gb
		$a_01_4 = {25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 47 62 50 6c 75 67 69 6e } //01 00  %programfiles%\GbPlugin
		$a_01_5 = {46 6f 6c 64 65 72 73 20 74 6f 20 64 65 6c 65 74 65 3a } //01 00  Folders to delete:
		$a_01_6 = {46 69 6c 65 73 20 74 6f 20 64 65 6c 65 74 65 3a } //01 00  Files to delete:
		$a_01_7 = {73 76 63 68 6f 73 74 2e 73 63 72 } //00 00  svchost.scr
	condition:
		any of ($a_*)
 
}