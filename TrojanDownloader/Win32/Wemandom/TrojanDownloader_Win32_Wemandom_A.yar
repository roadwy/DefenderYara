
rule TrojanDownloader_Win32_Wemandom_A{
	meta:
		description = "TrojanDownloader:Win32/Wemandom.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 31 33 30 38 30 2f 31 2e 65 78 65 00 } //01 00 
		$a_01_1 = {3a 31 33 30 38 30 2f 79 6b 2e 65 78 65 00 } //01 00 
		$a_01_2 = {3a 31 33 30 38 30 2f 71 71 2f 51 51 2e 65 78 65 00 } //01 00 
		$a_01_3 = {77 69 6e 64 6f 77 73 5c 61 61 65 6d 6d 61 2e 65 78 65 00 } //01 00 
		$a_01_4 = {77 69 6e 64 6f 77 73 5c 61 61 65 6d 6d 61 31 31 2e 65 78 65 00 } //01 00 
		$a_01_5 = {77 69 6e 64 6f 77 73 5c 65 6d 6d 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}