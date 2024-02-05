
rule TrojanDownloader_Win32_FakeQQ_A{
	meta:
		description = "TrojanDownloader:Win32/FakeQQ.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d e8 8d 45 ec ba 6c e9 4c 00 e8 de 58 f3 ff 8b 55 ec b9 7c e9 4c 00 b8 90 e9 4c 00 } //01 00 
		$a_01_1 = {b3 e4 d6 b5 b3 c9 b9 a6 00 00 00 00 b3 e4 d6 b5 b3 c9 b9 a6 c7 eb c9 d4 ba } //01 00 
		$a_01_2 = {53 65 6e 64 20 4f 4b 21 00 } //01 00 
		$a_03_3 = {6e 65 74 2f 90 02 10 2e 61 73 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}