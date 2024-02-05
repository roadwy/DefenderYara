
rule TrojanDownloader_Win32_FakeIA_A{
	meta:
		description = "TrojanDownloader:Win32/FakeIA.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05 53 } //01 00 
		$a_01_1 = {83 fb 32 7d 14 50 53 8b 45 0c 50 56 } //01 00 
		$a_03_2 = {53 68 2e 70 6e 67 00 90 09 02 00 69 90 00 } //01 00 
		$a_01_3 = {49 6e 73 65 63 75 72 65 20 42 72 6f 77 73 69 6e 67 20 45 72 72 6f 72 3a } //00 00 
	condition:
		any of ($a_*)
 
}