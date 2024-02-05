
rule TrojanDownloader_Win32_Agent_ZDL{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDL,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ff 92 f8 00 00 00 8b 45 ec 56 50 8b 08 ff 91 00 01 00 00 8b 45 ec 6a ff 50 8b 10 ff 92 f0 00 00 00 8b 45 ec 56 50 8b 08 ff 91 bc 00 00 00 8b 45 ec 56 50 8b 10 ff 92 a4 00 00 00 8b 45 ec 50 68 } //0a 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_00_2 = {68 74 74 70 3a 2f 2f 62 6f 74 2e 63 6a 66 65 65 64 73 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}