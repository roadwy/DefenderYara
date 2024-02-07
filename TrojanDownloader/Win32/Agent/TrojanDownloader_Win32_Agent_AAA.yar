
rule TrojanDownloader_Win32_Agent_AAA{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAA,SIGNATURE_TYPE_PEHSTR_EXT,29 00 28 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {83 ec 10 8d 44 24 04 50 68 1f 00 02 00 6a 00 68 90 01 02 41 00 68 01 00 00 80 c7 44 24 14 00 00 00 00 ff 15 90 01 02 41 00 85 c0 74 06 32 c0 83 c4 10 c3 90 00 } //0a 00 
		$a_02_1 = {2f 47 6f 6f 67 6c 65 5f 66 69 6c 65 73 2f 68 70 90 01 01 2e 67 69 66 90 00 } //0a 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 6e 65 77 20 57 57 57 5c 76 61 72 73 } //0a 00  Software\Microsoft\new WWW\vars
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 65 62 53 65 72 76 65 72 20 44 61 74 61 } //01 00  Software\Microsoft\WebServer Data
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}