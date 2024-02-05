
rule TrojanDownloader_Win32_Gabeerf_A{
	meta:
		description = "TrojanDownloader:Win32/Gabeerf.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 65 74 52 61 6e 64 6f 6d 00 2e 90 02 03 00 56 42 53 46 69 6c 65 00 2e 74 62 69 63 6f 00 90 00 } //01 00 
		$a_01_1 = {3a 37 37 37 2f 6c 6f 61 64 69 6e 67 2f 61 76 62 73 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}