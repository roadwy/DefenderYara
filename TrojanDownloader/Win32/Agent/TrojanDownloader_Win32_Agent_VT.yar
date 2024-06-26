
rule TrojanDownloader_Win32_Agent_VT{
	meta:
		description = "TrojanDownloader:Win32/Agent.VT,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 05 00 00 64 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 20 2f 73 20 } //0a 00  system32\regsvr32 /s 
		$a_02_1 = {40 40 00 55 8b 2d 90 01 02 40 00 56 8b 74 24 10 57 8b 3d 90 01 02 40 00 68 90 01 02 40 00 ff d3 68 90 01 04 ff d7 8b ce e8 90 01 02 00 00 85 c0 75 0b 8b ce e8 90 01 02 00 00 85 c0 74 f5 68 90 01 02 40 00 ff d5 eb d3 90 00 } //0a 00 
		$a_02_2 = {c7 44 24 0c 00 00 00 00 50 ff 15 90 01 02 40 00 8b 4c 24 18 8b 35 90 01 02 40 00 6a 00 51 ff d6 6a ff 56 ff 15 90 01 02 40 00 8d 4c 24 14 e8 90 01 04 8d 4c 24 18 c7 44 24 0c ff ff ff ff e8 90 00 } //01 00 
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_00_4 = {6f 70 65 6e 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}