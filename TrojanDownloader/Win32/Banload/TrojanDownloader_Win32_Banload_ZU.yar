
rule TrojanDownloader_Win32_Banload_ZU{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 63 00 72 00 90 02 0a 2e 00 65 00 78 00 65 00 00 90 02 16 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 90 02 26 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 90 02 26 2e 00 70 00 6e 00 67 00 00 90 02 30 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}