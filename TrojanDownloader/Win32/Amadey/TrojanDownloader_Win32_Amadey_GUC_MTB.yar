
rule TrojanDownloader_Win32_Amadey_GUC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Amadey.GUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f 43 ca 03 c1 3b f0 74 5d 8a 04 33 32 06 8b 57 10 8b 5f 14 88 45 ec 3b d3 73 28 8d 4a 01 89 4f 10 8b cf 83 fb 10 72 } //01 00 
		$a_01_1 = {41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //00 00  Amadey\Release\Amadey.pdb
	condition:
		any of ($a_*)
 
}