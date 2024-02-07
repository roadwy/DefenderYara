
rule TrojanDownloader_Win32_VB_OG{
	meta:
		description = "TrojanDownloader:Win32/VB.OG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 78 00 7a 00 31 00 39 00 2e 00 63 00 6f 00 6d 00 } //01 00  .xz19.com
		$a_03_1 = {2f 00 78 00 7a 00 7a 00 2f 00 90 01 02 2f 00 2f 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 5f 00 90 00 } //01 00 
		$a_03_2 = {2f 00 6d 00 79 00 69 00 65 00 2f 00 90 01 0e 2e 00 65 00 78 00 65 00 90 01 06 6c 00 6d 00 30 00 32 00 90 00 } //01 00 
		$a_01_3 = {40 00 2a 00 5c 00 41 00 46 00 3a 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 76 00 63 00 5c 00 53 00 5c 00 31 00 32 00 5c 00 31 00 2e 00 76 00 62 00 70 00 } //00 00  @*\AF:\Application\vc\S\12\1.vbp
	condition:
		any of ($a_*)
 
}