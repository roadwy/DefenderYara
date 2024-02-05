
rule TrojanDownloader_Win32_Agent_ZAI{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZAI,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {00 6f 75 68 20 62 61 62 } //01 00 
		$a_01_1 = {25 73 5c 25 73 2e 65 78 65 } //03 00 
		$a_01_2 = {25 73 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 22 25 73 22 20 25 73 } //01 00 
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //03 00 
		$a_01_4 = {2e 63 6f 2e 6b 72 2f } //01 00 
		$a_01_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 2a 2e 2a } //00 00 
	condition:
		any of ($a_*)
 
}