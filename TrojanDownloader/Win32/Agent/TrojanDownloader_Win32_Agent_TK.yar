
rule TrojanDownloader_Win32_Agent_TK{
	meta:
		description = "TrojanDownloader:Win32/Agent.TK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 38 2e 36 38 2e 31 30 31 2e 32 32 36 3a 37 37 37 2f 6c 6f 61 64 69 6e 67 2f } //01 00 
		$a_01_1 = {3a 37 37 37 2f 6e 68 62 76 79 65 75 64 73 2e 70 68 70 } //01 00 
		$a_01_2 = {3a 32 35 31 2f 70 6f 70 6f 70 6f 2e 70 68 70 3f 67 67 3d } //01 00 
		$a_01_3 = {3a 32 35 31 2f 62 75 6b 75 61 69 6c 65 2e 70 68 70 3f 64 66 3d } //01 00 
		$a_01_4 = {3a 32 35 31 2f 72 66 72 66 72 66 72 66 72 66 2e 70 68 70 3f 67 67 3d } //01 00 
		$a_01_5 = {3a 32 35 31 2f 64 65 6d 61 6d 61 63 61 6f 2e 70 68 70 2e 70 68 70 3f 64 66 3d } //00 00 
	condition:
		any of ($a_*)
 
}