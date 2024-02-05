
rule TrojanDownloader_Win32_Banload_QH{
	meta:
		description = "TrojanDownloader:Win32/Banload.QH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 6a 70 67 00 90 02 02 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 90 02 13 2e 63 70 6c 00 90 0a e0 00 00 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}