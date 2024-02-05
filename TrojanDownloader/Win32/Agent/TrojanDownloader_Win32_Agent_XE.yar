
rule TrojanDownloader_Win32_Agent_XE{
	meta:
		description = "TrojanDownloader:Win32/Agent.XE,SIGNATURE_TYPE_PEHSTR,0c 00 0b 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //01 00 
		$a_01_1 = {43 6f 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {5c 31 2e 65 78 65 } //01 00 
		$a_01_3 = {5c 32 2e 65 78 65 } //03 00 
		$a_01_4 = {2e 65 78 65 20 20 20 20 20 } //03 00 
		$a_01_5 = {55 8b ec b3 00 8b 75 08 ac 84 c0 74 09 3c 20 75 f7 4e 88 1e eb f2 c9 c2 04 } //03 00 
		$a_01_6 = {eb 16 8b 55 f8 8b 12 8d 45 f4 50 ff 75 f8 ff 52 38 6a 64 } //00 00 
	condition:
		any of ($a_*)
 
}