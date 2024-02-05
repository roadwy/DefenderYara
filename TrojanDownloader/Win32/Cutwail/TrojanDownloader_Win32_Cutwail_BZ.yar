
rule TrojanDownloader_Win32_Cutwail_BZ{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 72 75 6e 5f 6d 65 6d 00 } //01 00 
		$a_03_1 = {81 7d f8 44 41 54 41 74 90 01 01 81 7d f8 43 4d 44 20 74 90 01 01 81 7d f8 45 4e 44 2e 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}