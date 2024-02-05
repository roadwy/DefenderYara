
rule TrojanDownloader_Win32_Small_NCD{
	meta:
		description = "TrojanDownloader:Win32/Small.NCD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {40 00 6a 00 68 00 00 02 00 e8 90 01 02 00 00 83 f8 00 0f 90 01 05 68 90 01 02 40 00 6a 00 68 90 01 02 40 00 e8 90 00 } //01 00 
		$a_00_1 = {2f 63 20 64 65 6c 20 25 73 2e 65 78 65 } //01 00 
		$a_00_2 = {43 72 65 61 74 65 4d 75 74 65 78 } //01 00 
		$a_00_3 = {57 69 6e 45 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}