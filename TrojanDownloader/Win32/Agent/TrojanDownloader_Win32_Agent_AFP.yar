
rule TrojanDownloader_Win32_Agent_AFP{
	meta:
		description = "TrojanDownloader:Win32/Agent.AFP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 cb 08 e9 90 01 01 00 00 00 80 e3 f7 eb 7f f6 04 31 04 74 05 80 cb 04 eb 74 80 e3 fb eb 6f 90 00 } //01 00 
		$a_01_1 = {8a 11 80 c2 17 30 10 41 40 4f 75 ed } //01 00 
		$a_00_2 = {25 41 50 50 44 41 54 41 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 65 64 69 61 20 50 6c 61 79 65 72 5c 44 52 4d 31 32 38 } //01 00 
		$a_00_3 = {2f 70 61 74 63 68 2f 63 68 6b 75 70 64 61 74 65 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}