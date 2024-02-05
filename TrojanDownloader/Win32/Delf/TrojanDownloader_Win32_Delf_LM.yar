
rule TrojanDownloader_Win32_Delf_LM{
	meta:
		description = "TrojanDownloader:Win32/Delf.LM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00 
		$a_03_1 = {25 64 00 00 64 6b 65 90 01 09 78 7a 7a 2f 90 00 } //01 00 
		$a_03_2 = {63 74 66 6d 6f 6e 5f 90 02 31 71 72 6e 5f 90 01 0c 6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f 90 00 } //01 00 
		$a_03_3 = {43 6e 49 45 2e 74 6d 70 90 01 0c 6e 2e 74 6d 70 90 01 0b 6e 2e 65 78 65 90 01 03 64 6f 77 6e 32 90 01 03 6d 79 69 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}