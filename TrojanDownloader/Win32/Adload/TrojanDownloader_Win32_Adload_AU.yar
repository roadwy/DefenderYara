
rule TrojanDownloader_Win32_Adload_AU{
	meta:
		description = "TrojanDownloader:Win32/Adload.AU,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6c 2f 64 6c 75 6e 69 71 31 2e 70 68 70 3f 61 64 76 3d } //01 00  dl/dluniq1.php?adv=
		$a_00_1 = {41 6c 6c 6f 77 20 61 6c 6c 20 61 63 74 69 76 69 74 69 65 73 20 66 6f 72 20 74 68 69 73 20 61 70 70 6c 69 63 61 74 69 6f 6e } //01 00  Allow all activities for this application
		$a_01_2 = {74 6f 6f 6c 62 61 72 2e 74 78 74 00 5c 74 6f 6f 6c 34 2e 65 78 65 00 00 5c 74 6f 6f 6c 32 2e 65 78 65 } //01 00 
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //01 00  Software\Microsoft\Windows\CurrentVersion
		$a_00_4 = {26 52 65 6d 65 6d 62 65 72 20 74 68 69 73 20 61 6e 73 77 65 72 20 74 68 65 20 6e 65 78 74 20 74 69 6d 65 20 49 20 75 73 65 20 74 68 69 73 20 70 72 6f 67 72 61 6d 2e } //01 00  &Remember this answer the next time I use this program.
		$a_02_5 = {26 63 6f 64 65 31 3d 48 4e 4e 45 90 02 01 26 63 6f 64 65 32 3d 35 31 32 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}