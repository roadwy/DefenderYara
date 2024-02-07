
rule TrojanDownloader_Win32_Banload_AWW{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 48 61 63 6b 4d 65 6d 6f 72 79 53 74 72 65 61 6d 47 } //01 00  THackMemoryStreamG
		$a_02_1 = {61 00 6d 00 62 00 69 00 6c 00 6f 00 67 00 69 00 73 00 74 00 69 00 63 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6a 00 73 00 2f 00 5f 00 6e 00 6f 00 74 00 65 00 73 00 2f 00 90 02 30 2e 00 7a 00 69 00 70 00 90 00 } //01 00 
		$a_03_2 = {2e 00 65 00 78 00 65 00 00 90 02 04 4f 00 70 00 65 00 6e 00 90 02 20 41 00 63 00 65 00 73 00 73 00 6f 00 20 00 6e 00 65 00 67 00 61 00 64 00 6f 00 2e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}