
rule TrojanDownloader_Win32_Small_AABK{
	meta:
		description = "TrojanDownloader:Win32/Small.AABK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2e 68 74 6d 00 2e 61 73 70 00 2e 70 68 70 00 2e 61 73 70 78 00 2e 6a 73 70 00 2e 68 74 6d 6c 00 3c 69 66 72 61 6d 65 20 73 72 63 3d 90 02 30 3e 3c 2f 69 66 72 61 6d 65 3e 90 00 } //01 00 
		$a_02_1 = {53 76 63 68 6f 73 74 2e 65 78 65 90 02 20 2a 2e 2a 90 02 04 63 3a 5c 90 02 10 2e 73 79 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}