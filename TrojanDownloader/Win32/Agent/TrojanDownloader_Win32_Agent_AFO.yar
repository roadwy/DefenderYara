
rule TrojanDownloader_Win32_Agent_AFO{
	meta:
		description = "TrojanDownloader:Win32/Agent.AFO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 f6 74 09 66 81 7c 24 24 4d 5a 75 27 8b 54 24 10 } //01 00 
		$a_00_1 = {2f 2f 61 2e 7a 7a 37 2e 69 6e 2f 63 6f 75 6e 74 2e 61 73 70 } //01 00 
		$a_00_2 = {2f 2f 74 78 2e 78 78 37 2e 69 6e 2f 61 37 6c 6d 2e 74 78 74 } //01 00 
		$a_00_3 = {6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 6f 73 3d 25 73 26 74 6d 3d 25 73 26 69 64 3d 25 73 26 68 64 3d 25 73 26 } //01 00 
		$a_00_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 25 73 } //01 00 
		$a_00_5 = {73 6d 73 73 2e 65 78 65 7c 63 73 72 73 73 2e 65 78 65 7c 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 7c 73 65 72 76 69 63 65 73 2e 65 78 65 7c 73 76 63 68 6f 73 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}