
rule TrojanDownloader_Win32_Banload_OY{
	meta:
		description = "TrojanDownloader:Win32/Banload.OY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2e 6a 70 67 00 90 02 07 43 3a 5c 41 72 71 75 69 76 6f 90 02 03 64 65 20 70 72 6f 67 72 61 6d 61 90 02 30 2e 65 78 65 90 0a 90 00 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}