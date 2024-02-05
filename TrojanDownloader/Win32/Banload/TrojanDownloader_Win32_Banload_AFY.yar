
rule TrojanDownloader_Win32_Banload_AFY{
	meta:
		description = "TrojanDownloader:Win32/Banload.AFY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 00 6d 00 6d 00 6d 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_02_1 = {2e 00 72 00 75 00 2e 00 61 00 63 00 2e 00 62 00 64 00 2f 00 61 00 72 00 61 00 62 00 69 00 63 00 2f 00 6c 00 6f 00 67 00 73 00 2f 00 90 02 0f 2e 00 67 00 69 00 66 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}