
rule TrojanDownloader_Win32_Banload_AGR{
	meta:
		description = "TrojanDownloader:Win32/Banload.AGR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 8b 80 68 03 00 00 66 be eb ff e8 } //01 00 
		$a_01_1 = {73 65 74 75 70 2e 65 78 65 00 } //01 00 
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 00 } //01 00 
		$a_01_3 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 90 02 0a 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}