
rule TrojanDownloader_Win32_Snabif_A{
	meta:
		description = "TrojanDownloader:Win32/Snabif.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_1 = {68 74 74 70 3a 2f 2f 66 61 62 69 61 6e 73 2e 63 6e 2f 68 62 2f 90 02 02 2e 65 78 65 90 00 } //01 00 
		$a_00_2 = {70 72 63 76 69 65 77 } //01 00  prcview
		$a_00_3 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_02_4 = {f3 a5 66 a5 a4 b9 06 00 00 00 be 90 01 02 40 00 8d bd 90 01 02 ff ff f3 a5 66 a5 a4 b9 06 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}