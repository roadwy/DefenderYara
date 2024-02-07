
rule TrojanDownloader_Win32_Noitap_A{
	meta:
		description = "TrojanDownloader:Win32/Noitap.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 00 73 00 3f 00 2e 00 72 00 61 00 6e 00 64 00 3d 00 25 00 64 00 00 00 } //01 00 
		$a_00_1 = {58 58 53 65 72 76 69 63 65 2e 70 64 62 } //01 00  XXService.pdb
		$a_03_2 = {6a 3f 56 e8 90 01 04 83 c4 1c bb 90 01 04 85 c0 74 05 bb 90 01 04 e8 90 01 04 50 56 8d 54 24 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}