
rule TrojanDownloader_Win32_Renos_DY{
	meta:
		description = "TrojanDownloader:Win32/Renos.DY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 8c a4 01 00 00 55 56 57 8d 7c 24 38 } //01 00 
		$a_03_1 = {74 2f 6a 02 6a 00 6a fc 56 ff 15 90 01 04 83 f8 ff 74 1d 90 00 } //01 00 
		$a_01_2 = {5c 6d 73 78 6d 6c 37 31 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}