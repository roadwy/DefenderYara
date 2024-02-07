
rule TrojanDownloader_BAT_Loipaoc_A{
	meta:
		description = "TrojanDownloader:BAT/Loipaoc.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 } //01 00 
		$a_01_1 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //01 00  NtSetInformationProcess
		$a_01_2 = {6c 00 70 00 63 00 69 00 6c 00 } //01 00  lpcil
		$a_03_3 = {1f 1d 12 00 1a 28 90 01 01 00 00 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}