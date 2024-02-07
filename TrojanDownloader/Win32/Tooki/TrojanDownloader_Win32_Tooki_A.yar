
rule TrojanDownloader_Win32_Tooki_A{
	meta:
		description = "TrojanDownloader:Win32/Tooki.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 07 8a 4f 01 88 44 24 0c 8a 47 02 88 4c 24 0d 8a 4f 03 3c 3d 88 44 24 0e 88 4c 24 0f 74 90 01 01 8b 54 24 0c 80 f9 3d 90 00 } //0a 00 
		$a_00_1 = {8a 46 01 33 db 3c 41 0f 9c c3 4b 83 e3 07 0f be d0 83 c3 30 2b d3 83 fa 10 } //01 00 
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //01 00  SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {4e 65 74 77 6f 72 6b 20 4c 6f 63 61 74 69 6f 6e 20 41 77 61 72 65 6e 65 73 73 20 28 4e 4c 41 29 } //00 00  Network Location Awareness (NLA)
	condition:
		any of ($a_*)
 
}