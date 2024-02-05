
rule TrojanDownloader_Win32_Agent_ZCB{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZCB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 75 61 6e 67 7a 61 6f 68 75 69 68 75 61 6e 67 } //01 00 
		$a_01_1 = {77 77 77 2e 68 61 6f 61 64 73 2e 63 6e } //01 00 
		$a_01_2 = {63 68 75 61 6e 67 7a 61 6f 68 75 69 68 75 61 6e 67 2e 63 6e } //01 00 
		$a_01_3 = {6d 69 63 72 30 73 30 66 74 73 2e 63 6e } //01 00 
		$a_01_4 = {68 74 74 70 3a 2f 2f 75 6e 73 74 61 74 2e 62 61 69 64 75 2e 63 6f 6d } //01 00 
		$a_01_5 = {f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca } //00 00 
	condition:
		any of ($a_*)
 
}