
rule TrojanDownloader_Win32_Rugmi_SA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c1 83 c1 90 01 01 89 4c 24 90 01 01 83 f8 90 01 01 74 90 01 01 8b 44 24 90 01 01 8a 90 01 01 8b 0c 24 88 01 8b 04 24 83 c0 90 01 01 89 04 24 8b 44 24 90 01 01 83 c0 90 01 01 89 44 24 90 01 01 eb 90 00 } //01 00 
		$a_01_1 = {5c 4e 65 77 54 6f 6f 6c 73 50 72 6f 6a 65 63 74 5c 53 51 4c 69 74 65 33 45 6e 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 53 51 4c 69 74 65 33 45 6e 63 72 79 70 74 2e 70 64 62 } //00 00  \NewToolsProject\SQLite3Encrypt\Release\SQLite3Encrypt.pdb
	condition:
		any of ($a_*)
 
}