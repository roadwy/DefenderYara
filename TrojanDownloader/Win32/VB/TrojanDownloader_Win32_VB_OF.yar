
rule TrojanDownloader_Win32_VB_OF{
	meta:
		description = "TrojanDownloader:Win32/VB.OF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 00 78 00 7a 00 31 00 39 00 2e 00 63 00 6f 00 6d 00 90 01 1e 64 00 6f 00 77 00 6e 00 32 00 90 00 } //01 00 
		$a_01_1 = {20 00 2f 00 78 00 78 00 20 00 2f 00 78 00 7a 00 7a 00 2f 00 } //01 00   /xx /xzz/
		$a_01_2 = {20 00 2f 00 78 00 78 00 20 00 2f 00 6d 00 79 00 69 00 65 00 2f 00 } //01 00   /xx /myie/
		$a_01_3 = {40 00 2a 00 5c 00 41 00 46 00 3a 00 5c 00 39 00 33 00 35 00 39 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //00 00  @*\AF:\9359\Project1.vbp
	condition:
		any of ($a_*)
 
}