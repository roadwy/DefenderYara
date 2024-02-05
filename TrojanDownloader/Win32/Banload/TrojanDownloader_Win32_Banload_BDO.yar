
rule TrojanDownloader_Win32_Banload_BDO{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 42 33 53 2e 64 61 74 } //01 00 
		$a_01_1 = {5c 44 50 52 30 30 39 2e 65 78 65 } //01 00 
		$a_01_2 = {2f 61 63 65 73 73 61 72 2e 70 68 70 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}